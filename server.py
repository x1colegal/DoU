import argparse
import base64
import errno
import ipaddress
import os
import secrets
import shlex
import socket
import threading
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from aead_udp import AEADDatagramSocket, normalize_cipher_name
from dou_proto import TYPE_ERROR, TYPE_PING, TYPE_PONG, TYPE_QUERY, TYPE_RESPONSE, decode_frame, encode_frame, encode_json_frame
from packet import TYPE_ACK, TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, TYPE_RETRANSMIT_REQUEST, mkp
from ustp import USTPReceiver, USTPSender, parse_packet


HELLO_PREFIX = b"USTPS-KEX1\0"
CHALLENGE_PREFIX = b"USTPS-CHALLENGE1\0"
RESPONSE_PREFIX = b"USTPS-CHALLENGE-REPLY1\0"
SESSION_PREFIX = b"USTPS-SESSION1\0"
UDP_BUFFER_BYTES = 4 * 1024 * 1024
SYSTEMD_UNIT_PATH = "/etc/systemd/system/dou-server.service"
DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
DNS_TYPE_PTR = 12
DNS_CLASS_IN = 1
DNS_FLAG_QR = 0x8000
DNS_FLAG_RD = 0x0100
DNS_FLAG_RA = 0x0080
DNS_RCODE_MASK = 0x000F
DNS_RCODE_NOERROR = 0
DNS_RCODE_FORMERR = 1
DNS_RCODE_SERVFAIL = 2
DNS_RCODE_NXDOMAIN = 3
DNS_RCODE_NOTIMP = 4


@dataclass
class PendingChallenge:
    addr: tuple[str, int]
    client_pub: bytes
    cipher: str
    congestion_control: str
    cleartext: str
    session_id: str
    token: str
    created_ts: float


@dataclass
class ClientSession:
    addr: tuple[str, int]
    sender: USTPSender
    receiver: USTPReceiver
    cipher: str
    session_psk: bytes
    client_pub: bytes
    server_pub: bytes
    session_id: str
    session_reply: bytes
    cleartext: bool
    last_seen_ts: float = field(default_factory=time.time)


def public_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def derive_session_key(shared: bytes, client_pub: bytes, server_pub: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=client_pub + server_pub,
        info=b"USTPS-X25519-session-v1",
    ).derive(shared)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def parse_hello_options(raw: bytes) -> tuple[str | None, str | None, str | None]:
    if not raw:
        return None, None, None
    try:
        text = raw.decode("ascii", "replace")
    except Exception:
        return None, None, None
    parts = text.split("\0")
    cipher = normalize_cipher_name(parts[0]) if parts and parts[0] else None
    cc_mode = None
    cleartext_mode = None
    for part in parts[1:]:
        if part.startswith("cc="):
            value = part[3:].strip().lower()
            if value in {"on", "off"}:
                cc_mode = value
        elif part.startswith("ct="):
            value = part[3:].strip().lower()
            if value in {"on", "off"}:
                cleartext_mode = value
    return cipher, cc_mode, cleartext_mode


def resolve_server_cc_mode(server_mode: str, client_mode: str | None) -> str:
    if server_mode == "on":
        return "on"
    if server_mode == "off":
        return "off"
    return "on" if client_mode == "on" else "off"


def resolve_server_cleartext_mode(server_mode: str, client_mode: str | None) -> str:
    if server_mode == "on":
        return "on"
    if server_mode == "off":
        return "off"
    return "on" if client_mode == "on" else "off"


def parse_client_hello(payload: bytes):
    if payload.startswith(HELLO_PREFIX):
        rest = payload[len(HELLO_PREFIX):]
        if len(rest) < 32:
            return None
        client_pub = rest[:32]
        cipher = None
        cc_mode = None
        cleartext = None
        if len(rest) > 32:
            cipher, cc_mode, cleartext = parse_hello_options(rest[32:])
        return ("init", client_pub, cipher, cc_mode, cleartext)
    if payload.startswith(RESPONSE_PREFIX):
        rest = payload[len(RESPONSE_PREFIX):]
        parts = rest.split(b"\0", 5)
        if len(parts) != 6 or len(parts[5]) != 32:
            return None
        token = parts[0].decode("ascii", "replace")
        session_id = parts[1].decode("ascii", "replace")
        cipher, cc_mode, cleartext = parse_hello_options(parts[2] + b"\0" + parts[3] + b"\0" + parts[4])
        if cipher is None:
            return None
        return ("challenge_reply", token, session_id, parts[5], cipher, cc_mode, cleartext)
    return None


def load_or_create_host_key(path: str) -> x25519.X25519PrivateKey:
    try:
        with open(path, "rb") as f:
            raw = f.read()
        if len(raw) == 32:
            return x25519.X25519PrivateKey.from_private_bytes(raw)
    except FileNotFoundError:
        pass
    key = x25519.X25519PrivateKey.generate()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return key


def systemd_available() -> bool:
    return os.path.isdir("/run/systemd/system") and os.path.isdir("/etc/systemd/system")


def maybe_prompt_dns64(args: argparse.Namespace) -> None:
    if not os.isatty(0):
        return
    if args.dns64 != "off":
        return
    answer = input("Enable DNS64 on this DoU server? [y/N] ").strip().lower()
    if answer in ("y", "yes"):
        args.dns64 = "on"
        prefix = input(f"DNS64 prefix [{args.dns64_prefix}]: ").strip()
        if prefix:
            args.dns64_prefix = prefix


def build_systemd_unit(args: argparse.Namespace) -> str:
    cmd = [
        "python3",
        os.path.abspath(__file__),
        "--start",
        "--dns64", args.dns64,
    ]
    if args.dns64_prefix != "64:ff9b::/96":
        cmd.extend(["--dns64-prefix", args.dns64_prefix])
    if args.bind_port != 4053:
        cmd.extend(["--bind-port", str(args.bind_port)])
    exec_start = " ".join(shlex.quote(part) for part in cmd)
    return (
        "[Unit]\n"
        "Description=DoU server (DNS-over-USTPS)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"WorkingDirectory={shlex.quote(os.path.dirname(os.path.abspath(__file__)))}\n"
        f"ExecStart={exec_start}\n"
        "Restart=always\n"
        "RestartSec=2\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def maybe_install_systemd(args: argparse.Namespace) -> None:
    if not systemd_available():
        return
    if os.geteuid() != 0:
        return
    unit_text = build_systemd_unit(args)
    current = None
    try:
        with open(SYSTEMD_UNIT_PATH, "r", encoding="utf-8") as f:
            current = f.read()
    except FileNotFoundError:
        pass
    if current != unit_text:
        with open(SYSTEMD_UNIT_PATH, "w", encoding="utf-8") as f:
            f.write(unit_text)
        print(f"[DoU-SERVER] systemd unit updated at {SYSTEMD_UNIT_PATH}")
    os.system("systemctl daemon-reload >/dev/null 2>&1")
    os.system("systemctl enable dou-server.service >/dev/null 2>&1")
    if current is None:
        print(f"[DoU-SERVER] systemd unit installed automatically at {SYSTEMD_UNIT_PATH}")


def maybe_configure_and_exit(args: argparse.Namespace) -> None:
    if args.start:
        return
    maybe_install_systemd(args)
    print("[DoU-SERVER] configuration completed")
    raise SystemExit(0)


def tune_udp_socket(sock: socket.socket) -> None:
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, UDP_BUFFER_BYTES)
        except OSError:
            pass


def create_server_udp_socket(bind_ip: str, bind_port: int) -> socket.socket:
    bind_host = "::" if bind_ip == "0.0.0.0" else bind_ip
    infos = socket.getaddrinfo(bind_host, bind_port, socket.AF_UNSPEC, socket.SOCK_DGRAM, 0, socket.AI_PASSIVE)
    last_error = None
    for family, socktype, proto, _, sockaddr in infos:
        try:
            sock = socket.socket(family, socktype, proto)
            if family == socket.AF_INET6:
                try:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except OSError:
                    pass
            tune_udp_socket(sock)
            sock.bind(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise OSError(errno.EADDRNOTAVAIL, "unable to bind DoU UDP socket")


def dns_read_name(message: bytes, offset: int, depth: int = 0) -> tuple[bytes, int]:
    if depth > 10:
        raise ValueError("DNS name pointer recursion too deep")
    labels: list[bytes] = []
    original_offset = offset
    jumped = False
    while True:
        if offset >= len(message):
            raise ValueError("DNS name exceeds message")
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            pointed, _ = dns_read_name(message, pointer, depth + 1)
            labels.extend(pointed.split(b".") if pointed else [])
            offset += 2
            jumped = True
            break
        if length == 0:
            offset += 1
            break
        offset += 1
        if offset + length > len(message):
            raise ValueError("truncated DNS label")
        labels.append(message[offset : offset + length])
        offset += length
    name = b".".join(label for label in labels if label)
    return name, (offset if not jumped else original_offset + 2)


def dns_parse_question(message: bytes) -> dict | None:
    if len(message) < 12:
        return None
    qdcount = int.from_bytes(message[4:6], "big")
    if qdcount < 1:
        return None
    try:
        _, offset = dns_read_name(message, 12)
    except Exception:
        return None
    if offset + 4 > len(message):
        return None
    return {
        "question_end": offset + 4,
        "qtype": int.from_bytes(message[offset : offset + 2], "big"),
        "qclass": int.from_bytes(message[offset + 2 : offset + 4], "big"),
        "flags": int.from_bytes(message[2:4], "big"),
    }


def dns_replace_qtype(message: bytes, qtype: int) -> bytes:
    question = dns_parse_question(message)
    if question is None:
        return message
    end = question["question_end"]
    qtype_offset = end - 4
    return message[:qtype_offset] + qtype.to_bytes(2, "big") + message[qtype_offset + 2 :]


def dns_qtype_name(qtype: int) -> str:
    if qtype == DNS_TYPE_A:
        return "A"
    if qtype == DNS_TYPE_AAAA:
        return "AAAA"
    if qtype == DNS_TYPE_PTR:
        return "PTR"
    return f"TYPE{qtype}"


def dns_wire_name_from_text(name: str) -> bytes:
    stripped = name.strip(".")
    if not stripped:
        return b"\x00"
    out = bytearray()
    for label in stripped.split("."):
        encoded = label.encode("idna")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def synthesize_nat64_ipv6(ipv4_text: str, dns64_prefix: ipaddress.IPv6Network) -> bytes:
    ipv4_int = int(ipaddress.IPv4Address(ipv4_text))
    ipv6_int = int(dns64_prefix.network_address) | ipv4_int
    return ipaddress.IPv6Address(ipv6_int).packed


def dns_build_response(query: bytes, qtype: int, answers: list[tuple[int, bytes]], rcode: int = DNS_RCODE_NOERROR) -> bytes | None:
    question = dns_parse_question(query)
    if question is None:
        return None
    flags = (int.from_bytes(query[2:4], "big") & DNS_FLAG_RD) | DNS_FLAG_QR | DNS_FLAG_RA | (rcode & DNS_RCODE_MASK)
    qname_wire = query[12 : question["question_end"] - 4]
    qclass_wire = query[question["question_end"] - 2 : question["question_end"]]
    body = bytearray()
    for ttl, rdata in answers:
        body.extend(b"\xC0\x0C")
        body.extend(qtype.to_bytes(2, "big"))
        body.extend(qclass_wire)
        body.extend(ttl.to_bytes(4, "big"))
        body.extend(len(rdata).to_bytes(2, "big"))
        body.extend(rdata)
    header = bytearray()
    header.extend(query[0:2])
    header.extend(flags.to_bytes(2, "big"))
    header.extend((1).to_bytes(2, "big"))
    header.extend(len(answers).to_bytes(2, "big"))
    header.extend((0).to_bytes(2, "big"))
    header.extend((0).to_bytes(2, "big"))
    return bytes(header) + qname_wire + qtype.to_bytes(2, "big") + qclass_wire + bytes(body)


def resolve_with_python(query: bytes, dns64_enabled: bool, dns64_prefix: ipaddress.IPv6Network) -> tuple[bytes | None, str, str]:
    question = dns_parse_question(query)
    if question is None or question["qclass"] != DNS_CLASS_IN:
        return dns_build_response(query, DNS_TYPE_A, [], DNS_RCODE_FORMERR), "<invalid>", "FORMERR"
    try:
        qname_bytes, _ = dns_read_name(query, 12)
    except Exception:
        return dns_build_response(query, question["qtype"], [], DNS_RCODE_FORMERR), "<invalid>", "FORMERR"
    try:
        qname = qname_bytes.decode("ascii")
    except UnicodeDecodeError:
        qname = qname_bytes.decode("ascii", "ignore")
    ttl = 60

    try:
        if question["qtype"] == DNS_TYPE_A:
            infos = socket.getaddrinfo(qname, None, socket.AF_INET, socket.SOCK_STREAM)
            seen = set()
            answers = []
            for _, _, _, _, sockaddr in infos:
                ip = sockaddr[0]
                if ip in seen:
                    continue
                seen.add(ip)
                answers.append((ttl, ipaddress.IPv4Address(ip).packed))
            return dns_build_response(query, DNS_TYPE_A, answers, DNS_RCODE_NOERROR), qname, f"NOERROR answers={len(answers)}"
        if question["qtype"] == DNS_TYPE_AAAA:
            if dns64_enabled and qname.lower().endswith(".nat64"):
                raw_ipv4 = qname[:-6].rstrip(".")
                try:
                    synthesized = synthesize_nat64_ipv6(raw_ipv4, dns64_prefix)
                    return (
                        dns_build_response(query, DNS_TYPE_AAAA, [(ttl, synthesized)], DNS_RCODE_NOERROR),
                        qname,
                        "DNS64 literal answers=1",
                    )
                except ipaddress.AddressValueError:
                    pass
            infos = []
            try:
                infos = socket.getaddrinfo(qname, None, socket.AF_INET6, socket.SOCK_STREAM)
            except socket.gaierror as exc:
                no_aaaa_errors = {getattr(socket, "EAI_NONAME", -2), getattr(socket, "EAI_NODATA", -5), -5}
                if exc.errno not in no_aaaa_errors:
                    raise
            seen = set()
            answers = []
            for _, _, _, _, sockaddr in infos:
                ip = sockaddr[0]
                if ip in seen:
                    continue
                seen.add(ip)
                answers.append((ttl, ipaddress.IPv6Address(ip).packed))
            if answers:
                return dns_build_response(query, DNS_TYPE_AAAA, answers, DNS_RCODE_NOERROR), qname, f"NOERROR answers={len(answers)}"
            if dns64_enabled:
                infos4 = socket.getaddrinfo(qname, None, socket.AF_INET, socket.SOCK_STREAM)
                seen4 = set()
                synth = []
                for _, _, _, _, sockaddr in infos4:
                    ip4 = sockaddr[0]
                    if ip4 in seen4:
                        continue
                    seen4.add(ip4)
                    synth.append((ttl, synthesize_nat64_ipv6(ip4, dns64_prefix)))
                return dns_build_response(query, DNS_TYPE_AAAA, synth, DNS_RCODE_NOERROR), qname, f"DNS64 answers={len(synth)}"
            return dns_build_response(query, DNS_TYPE_AAAA, [], DNS_RCODE_NOERROR), qname, "NOERROR answers=0"
        if question["qtype"] == DNS_TYPE_PTR:
            host, _ = socket.getnameinfo((qname.rstrip("."), 0), socket.NI_NAMEREQD)
            return dns_build_response(query, DNS_TYPE_PTR, [(ttl, dns_wire_name_from_text(host))], DNS_RCODE_NOERROR), qname, "NOERROR answers=1"
        return dns_build_response(query, question["qtype"], [], DNS_RCODE_NOTIMP), qname, "NOTIMP"
    except socket.gaierror as exc:
        if exc.errno == socket.EAI_NONAME:
            return dns_build_response(query, question["qtype"], [], DNS_RCODE_NXDOMAIN), qname, "NXDOMAIN"
        return dns_build_response(query, question["qtype"], [], DNS_RCODE_SERVFAIL), qname, f"SERVFAIL gaierror={exc.errno}"
    except Exception:
        return dns_build_response(query, question["qtype"], [], DNS_RCODE_SERVFAIL), qname, "SERVFAIL"


def main() -> None:
    ap = argparse.ArgumentParser(description="DoU server: DNS over USTPS")
    ap.add_argument("--start", action="store_true")
    ap.add_argument("--bind-port", type=int, default=4053)
    ap.add_argument("--dns64", choices=["on", "off"], default="off")
    ap.add_argument("--dns64-prefix", default="64:ff9b::/96")
    args = ap.parse_args()

    maybe_prompt_dns64(args)
    dns64_prefix = ipaddress.IPv6Network(args.dns64_prefix, strict=True)
    args.bind_ip = "0.0.0.0"
    args.cipher = "auto"
    args.congestion_control = "off"
    args.cleartext = "off"
    args.host_key_file = os.path.expanduser("~/.dou_host_key")
    args.window = 1024
    args.rto = 0.20
    args.loss = 0

    maybe_configure_and_exit(args)

    raw_sock = create_server_udp_socket("0.0.0.0", args.bind_port)
    selected_cipher = None if args.cipher == "auto" else normalize_cipher_name(args.cipher)
    host_private = load_or_create_host_key(args.host_key_file)
    host_public = public_bytes(host_private.public_key())
    sock = AEADDatagramSocket(raw_sock, cipher_name=selected_cipher or "chacha20")

    sessions: dict[tuple[str, int], ClientSession] = {}
    pending_challenges: dict[tuple[str, int], PendingChallenge] = {}
    sessions_lock = threading.RLock()
    running = True

    print(
        f"[DoU-SERVER] listen=0.0.0.0:{args.bind_port} "
        f"dns64={args.dns64} prefix={dns64_prefix}"
    )

    def send_challenge(addr: tuple[str, int], client_pub_raw: bytes, requested_cipher: str | None, requested_cc: str | None, requested_cleartext: str | None) -> None:
        cipher = selected_cipher or requested_cipher or "chacha20"
        cc_mode = resolve_server_cc_mode(args.congestion_control, requested_cc)
        cleartext_mode = resolve_server_cleartext_mode(args.cleartext, requested_cleartext)
        print(
            f"[DoU-SERVER] challenge {addr[0]}:{addr[1]} "
            f"req_cipher={requested_cipher!r} req_cc={requested_cc!r} req_cleartext={requested_cleartext!r} "
            f"final_cipher={cipher} final_cc={cc_mode} final_cleartext={cleartext_mode}"
        )
        challenge = PendingChallenge(
            addr=addr,
            client_pub=client_pub_raw,
            cipher=cipher,
            congestion_control=cc_mode,
            cleartext=cleartext_mode,
            session_id=b64u(secrets.token_bytes(18)),
            token=b64u(secrets.token_bytes(18)),
            created_ts=time.time(),
        )
        pending_challenges[addr] = challenge
        payload = (
            CHALLENGE_PREFIX
            + challenge.token.encode("ascii")
            + b"\0"
            + challenge.session_id.encode("ascii")
            + b"\0"
            + challenge.cipher.encode("ascii")
            + b"\0cc="
            + challenge.congestion_control.encode("ascii")
            + b"\0ct="
            + challenge.cleartext.encode("ascii")
            + b"\0"
            + host_public
        )
        sock.send_plain(mkp(TYPE_HELLO, payload=payload).to_bytes(), addr)

    def send_app(session: ClientSession, payload: bytes) -> None:
        session.sender.queue_payload(payload)

    def finish_session(session: ClientSession) -> None:
        try:
            session.sender.stop()
        except Exception:
            pass
        try:
            sock.clear_peer(session.addr)
        except Exception:
            pass

    def resolve_dns_for_session(session: ClientSession, request_id: int, query: bytes) -> None:
        def worker() -> None:
            try:
                question = dns_parse_question(query)
                qtype = question["qtype"] if question is not None else -1
                response, qname, result = resolve_with_python(query, args.dns64 == "on", dns64_prefix)
                if response is None:
                    raise ValueError("invalid DNS query")
                print(
                    f"[DoU-SERVER] dns {session.addr[0]}:{session.addr[1]} "
                    f"{dns_qtype_name(qtype)} {qname} -> {result}"
                )
                send_app(session, encode_frame(TYPE_RESPONSE, request_id, response))
            except Exception as exc:
                send_app(session, encode_json_frame(TYPE_ERROR, request_id, {"message": f"python resolver failure: {exc}"}))
        threading.Thread(target=worker, daemon=True).start()

    def new_session(addr: tuple[str, int], challenge: PendingChallenge) -> ClientSession:
        client_pub = x25519.X25519PublicKey.from_public_bytes(challenge.client_pub)
        session_psk = derive_session_key(host_private.exchange(client_pub), challenge.client_pub, host_public)
        session_reply = (
            SESSION_PREFIX
            + challenge.session_id.encode("ascii")
            + b"\0"
            + challenge.cipher.encode("ascii")
            + b"\0cc="
            + challenge.congestion_control.encode("ascii")
            + b"\0ct="
            + challenge.cleartext.encode("ascii")
            + b"\0"
            + host_public
        )
        sock.send_plain(mkp(TYPE_HELLO, payload=session_reply).to_bytes(), addr)
        sock.set_peer_psk(addr, session_psk, challenge.cipher, cleartext=(challenge.cleartext == "on"))
        sender = USTPSender(
            sock=sock,
            peer=addr,
            window=args.window,
            rto=args.rto,
            loss_percent=args.loss,
            max_burst=1024,
            pump_interval=0.0005,
            congestion_control=(challenge.congestion_control == "on"),
        )
        sender.start()
        receiver = USTPReceiver(sock=sock, peer=addr)
        session = ClientSession(
            addr=addr,
            sender=sender,
            receiver=receiver,
            cipher=challenge.cipher,
            session_psk=session_psk,
            client_pub=challenge.client_pub,
            server_pub=host_public,
            session_id=challenge.session_id,
            session_reply=session_reply,
            cleartext=(challenge.cleartext == "on"),
        )
        sessions[addr] = session
        print(
            f"[DoU-SERVER] session ready {addr[0]}:{addr[1]} "
            f"cipher={challenge.cipher} cc={challenge.congestion_control} cleartext={challenge.cleartext}"
        )
        return session

    try:
        while running:
            raw, addr = sock.recvfrom(65535)
            pkt = parse_packet(raw)
            if pkt is None:
                continue

            with sessions_lock:
                session = sessions.get(addr)
                if session is not None:
                    session.last_seen_ts = time.time()

            if pkt.pkt_type == TYPE_HELLO:
                parsed = parse_client_hello(pkt.payload)
                if parsed is None:
                    continue
                if parsed[0] == "init":
                    _, client_pub, requested_cipher, requested_cc, requested_cleartext = parsed
                    with sessions_lock:
                        send_challenge(addr, client_pub, requested_cipher, requested_cc, requested_cleartext)
                    continue
                if parsed[0] == "challenge_reply":
                    _, token, session_id, client_pub, requested_cipher, requested_cc, requested_cleartext = parsed
                    with sessions_lock:
                        pending = pending_challenges.get(addr)
                        if (
                            pending is None
                            or pending.token != token
                            or pending.session_id != session_id
                            or pending.client_pub != client_pub
                            or pending.cipher != requested_cipher
                            or pending.congestion_control != (requested_cc or pending.congestion_control)
                            or pending.cleartext != (requested_cleartext or pending.cleartext)
                        ):
                            continue
                        new_session(addr, pending)
                        pending_challenges.pop(addr, None)
                    continue

            with sessions_lock:
                session = sessions.get(addr)
            if session is None:
                continue

            if pkt.pkt_type == TYPE_CLOSE:
                finish_session(session)
                with sessions_lock:
                    sessions.pop(addr, None)
                continue

            if pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, TYPE_HELLO):
                session.sender.on_control(pkt)
                continue

            if pkt.pkt_type != TYPE_DATA:
                continue

            payload = session.receiver.handle_data(pkt)
            session.receiver.maybe_nack()
            if not payload:
                continue
            frame = decode_frame(payload)
            if frame is None:
                continue

            if frame["type"] == TYPE_QUERY:
                resolve_dns_for_session(session, frame["request_id"], frame["payload"])
                continue
            if frame["type"] == TYPE_PING:
                send_app(session, encode_frame(TYPE_PONG, frame["request_id"], frame["payload"]))
                continue
    except KeyboardInterrupt:
        print("[DoU-SERVER] interrupted")
    finally:
        for session in list(sessions.values()):
            finish_session(session)
        raw_sock.close()


if __name__ == "__main__":
    main()
