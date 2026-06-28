import argparse
import errno
import ipaddress
import json
import os
import shlex
import socket
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from aead_udp import AEADDatagramSocket, normalize_cipher_name
from dou_proto import TYPE_ERROR, TYPE_PING, TYPE_PONG, TYPE_QUERY, TYPE_RESPONSE, decode_frame, decode_json_payload, encode_frame
from packet import TYPE_ACK, TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, TYPE_RETRANSMIT_REQUEST, mkp
from ustp import USTPReceiver, USTPSender, parse_packet


HELLO_PREFIX = b"USTPS-KEX1\0"
CHALLENGE_PREFIX = b"USTPS-CHALLENGE1\0"
RESPONSE_PREFIX = b"USTPS-CHALLENGE-REPLY1\0"
SESSION_PREFIX = b"USTPS-SESSION1\0"
UDP_BUFFER_BYTES = 4 * 1024 * 1024
SYSTEMD_UNIT_PATH = "/etc/systemd/system/dou-client.service"
DNSMASQ_CONF_PATH = "/etc/dnsmasq.conf"
DNS_FLAG_QR = 0x8000
DNS_FLAG_RD = 0x0100
DNS_FLAG_RA = 0x0080
DNS_RCODE_SERVFAIL = 2


def public_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def derive_session_key(shared: bytes, client_pub: bytes, server_pub: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=client_pub + server_pub,
        info=b"USTPS-X25519-session-v1",
    ).derive(shared)


def encode_transport_hello(client_pub: bytes, cipher: str, cc_mode: str, cleartext_mode: str) -> bytes:
    return HELLO_PREFIX + client_pub + cipher.encode("ascii") + b"\0cc=" + cc_mode.encode("ascii") + b"\0ct=" + cleartext_mode.encode("ascii")


def load_tofu(path: str) -> dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}
    return {}


def save_tofu(path: str, data: dict[str, str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def confirm_regen(peer_label: str) -> bool:
    if not os.isatty(0):
        return False
    answer = input(f"TOFU key changed for {peer_label}. Accept and replace stored key? [y/N] ").strip().lower()
    return answer in ("y", "yes")


def check_tofu(path: str, peer_label: str, server_pub: bytes, allow_regen: bool = False) -> None:
    db = load_tofu(path)
    fp = server_pub.hex()
    known = db.get(peer_label)
    if known is None:
        db[peer_label] = fp
        save_tofu(path, db)
        print(f"[DoU-CLIENT] TOFU trust established for {peer_label}")
        return
    if known != fp:
        if allow_regen and confirm_regen(peer_label):
            db[peer_label] = fp
            save_tofu(path, db)
            print(f"[DoU-CLIENT] TOFU key replaced for {peer_label}")
            return
        raise SystemExit(f"TOFU mismatch for {peer_label}: possible MITM or server key change")


def tune_udp_socket(sock: socket.socket) -> None:
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, UDP_BUFFER_BYTES)
        except OSError:
            pass


def resolve_peer_candidates(host: str, port: int):
    normalized = host.strip().strip("[]")
    try:
        ip = ipaddress.ip_address(normalized)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        sockaddr = (str(ip), port, 0, 0) if family == socket.AF_INET6 else (str(ip), port)
        return [(family, sockaddr)]
    except ValueError:
        pass
    infos = socket.getaddrinfo(normalized, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    out = []
    seen = set()
    for family in (socket.AF_INET6, socket.AF_INET):
        for fam, _, _, _, sockaddr in infos:
            if fam != family:
                continue
            key = (fam, sockaddr)
            if key in seen:
                continue
            seen.add(key)
            out.append((fam, sockaddr))
    return out


def bind_udp_socket(bind_ip: str, bind_port: int, family: int) -> socket.socket:
    bind_host = bind_ip
    if family == socket.AF_INET6 and bind_host == "0.0.0.0":
        bind_host = "::"
    if family == socket.AF_INET and bind_host == "::":
        bind_host = "0.0.0.0"
    sock = socket.socket(family, socket.SOCK_DGRAM)
    tune_udp_socket(sock)
    if family == socket.AF_INET6:
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        except OSError:
            pass
        sock.bind((bind_host, bind_port, 0, 0))
    else:
        sock.bind((bind_host, bind_port))
    return sock


def systemd_available() -> bool:
    return os.path.isdir("/run/systemd/system") and os.path.isdir("/etc/systemd/system")


def parse_server_value(server: str, default_port: int) -> tuple[str, int]:
    value = server.strip()
    if not value:
        raise ValueError("empty server value")
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise ValueError("invalid bracketed IPv6 server")
        host = value[1:end].strip()
        rest = value[end + 1 :]
        if not rest:
            return host, default_port
        if not rest.startswith(":"):
            raise ValueError("invalid server suffix")
        port = int(rest[1:])
        return host, port
    if value.count(":") == 1:
        host, maybe_port = value.rsplit(":", 1)
        if maybe_port.isdigit():
            return host.strip(), int(maybe_port)
    return value, default_port


def prompt_server_value(default_port: int) -> tuple[str, int]:
    while True:
        raw = input("DoU server (host, IPv4, IPv6, or host:port): ").strip()
        if not raw:
            continue
        try:
            return parse_server_value(raw, default_port)
        except Exception as exc:
            print(f"[DoU-CLIENT] invalid server value: {exc}")


def format_dnsmasq_server_line(host: str, port: int) -> str:
    return f"server={host}#{port}"


def dns_question_end(message: bytes) -> int | None:
    if len(message) < 12:
        return None
    qdcount = int.from_bytes(message[4:6], "big")
    if qdcount < 1:
        return None
    offset = 12
    while True:
        if offset >= len(message):
            return None
        length = message[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:
            return None
        offset += 1 + length
        if offset > len(message):
            return None
    if offset + 4 > len(message):
        return None
    return offset + 4


def build_dns_servfail(query: bytes) -> bytes | None:
    end = dns_question_end(query)
    if end is None:
        return None
    flags = (int.from_bytes(query[2:4], "big") & DNS_FLAG_RD) | DNS_FLAG_QR | DNS_FLAG_RA | DNS_RCODE_SERVFAIL
    header = bytearray()
    header.extend(query[0:2])
    header.extend(flags.to_bytes(2, "big"))
    header.extend((1).to_bytes(2, "big"))
    header.extend((0).to_bytes(2, "big"))
    header.extend((0).to_bytes(2, "big"))
    header.extend((0).to_bytes(2, "big"))
    return bytes(header) + query[12:end]


def build_systemd_unit(args: argparse.Namespace, server_host: str, server_port: int) -> str:
    cmd = [
        "python3",
        os.path.abspath(__file__),
        "--start",
        "--server",
        server_host if server_port == 4053 else f"{server_host}:{server_port}",
    ]
    if args.local_dns_port != 4333:
        cmd.extend(["--local-dns-port", str(args.local_dns_port)])
    exec_start = " ".join(shlex.quote(part) for part in cmd)
    return (
        "[Unit]\n"
        "Description=DoU client (DNS-over-USTPS)\n"
        "After=network-online.target dnsmasq.service\n"
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


def configure_dnsmasq(local_ip: str, local_port: int) -> None:
    line = format_dnsmasq_server_line(local_ip, local_port)
    no_resolv_line = "no-resolv"
    try:
        with open(DNSMASQ_CONF_PATH, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        lines = []
    filtered = [
        existing
        for existing in lines
        if existing.strip() != line
        and existing.strip() != no_resolv_line
        and existing.strip() != f"server=127.0.0.1#{local_port}"
        and existing.strip() != f"server=[::1]#{local_port}"
        and existing.strip() != f"server=::1#{local_port}"
    ]
    filtered.append(no_resolv_line)
    filtered.append(line)
    new_content = "\n".join(filtered).rstrip() + "\n"
    with open(DNSMASQ_CONF_PATH, "w", encoding="utf-8") as f:
        f.write(new_content)
    for cmd in (
        "systemctl reload dnsmasq >/dev/null 2>&1",
        "systemctl restart dnsmasq >/dev/null 2>&1",
        "service dnsmasq reload >/dev/null 2>&1",
        "service dnsmasq restart >/dev/null 2>&1",
    ):
        if os.system(cmd) == 0:
            break
    print(f"[DoU-CLIENT] dnsmasq configured to use {local_ip}:{local_port}")


def maybe_install_systemd(args: argparse.Namespace, server_host: str, server_port: int) -> None:
    if not systemd_available():
        return
    if os.geteuid() != 0:
        return
    unit_text = build_systemd_unit(args, server_host, server_port)
    current = None
    try:
        with open(SYSTEMD_UNIT_PATH, "r", encoding="utf-8") as f:
            current = f.read()
    except FileNotFoundError:
        pass
    if current != unit_text:
        with open(SYSTEMD_UNIT_PATH, "w", encoding="utf-8") as f:
            f.write(unit_text)
        print(f"[DoU-CLIENT] systemd unit updated at {SYSTEMD_UNIT_PATH}")
    configure_dnsmasq(args.local_dns_ip, args.local_dns_port)
    os.system("systemctl daemon-reload >/dev/null 2>&1")
    os.system("systemctl enable dou-client.service >/dev/null 2>&1")
    if current is None:
        print(f"[DoU-CLIENT] systemd unit installed automatically at {SYSTEMD_UNIT_PATH}")


def maybe_configure_and_exit(args: argparse.Namespace, server_host: str, server_port: int) -> None:
    if args.start:
        return
    maybe_install_systemd(args, server_host, server_port)
    print("[DoU-CLIENT] configuration completed")
    raise SystemExit(0)


def main() -> None:
    ap = argparse.ArgumentParser(description="DoU client: local DNS UDP -> USTPS")
    ap.add_argument("--start", action="store_true")
    ap.add_argument("--server", help="DoU server host/IP, optionally host:port or [IPv6]:port")
    ap.add_argument("--peer-ip", help="legacy alias for --server host/IP")
    ap.add_argument("--peer-port", type=int, default=4053)
    ap.add_argument("--local-dns-port", type=int, default=4333)
    args = ap.parse_args()

    if args.server:
        server_host, server_port = parse_server_value(args.server, args.peer_port)
    elif args.peer_ip:
        server_host, server_port = args.peer_ip, args.peer_port
    elif os.isatty(0):
        server_host, server_port = prompt_server_value(args.peer_port)
    else:
        raise SystemExit("DoU client requires --server when stdin is not interactive")

    args.peer_ip = server_host
    args.peer_port = server_port

    args.bind_ip = "0.0.0.0"
    args.bind_port = 0
    args.local_dns_ip = "::1"
    args.cipher = "chacha20"
    args.congestion_control = "off"
    args.cleartext = "off"
    args.tofu_file = os.path.expanduser("~/.dou_known_hosts.json")
    args.regen_key = False
    args.request_timeout = 5.0

    maybe_configure_and_exit(args, server_host, server_port)

    selected_cipher = normalize_cipher_name(args.cipher)
    tofu_label = f"{server_host}:{server_port}"
    client_private = x25519.X25519PrivateKey.generate()
    client_pub = public_bytes(client_private.public_key())

    raw_usock = None
    usock = None
    peer = None
    sender = None
    receiver = None
    pending: dict[int, tuple[tuple, float, bytes]] = {}
    pending_lock = threading.RLock()
    req_counter = 1
    running = True

    def next_request_id() -> int:
        nonlocal req_counter
        with pending_lock:
            rid = req_counter
            req_counter = (req_counter + 1) & 0xFFFFFFFF
            if req_counter == 0:
                req_counter = 1
            return rid

    def connect_transport() -> None:
        nonlocal raw_usock, usock, peer, sender, receiver
        candidates = resolve_peer_candidates(args.peer_ip, args.peer_port)
        if not candidates:
            raise SystemExit("no DoU peer candidates")

        for family, sockaddr in candidates:
            print(f"[DoU-CLIENT] trying candidate family={family} addr={sockaddr}")
            raw_candidate = bind_udp_socket(args.bind_ip, args.bind_port, family)
            raw_candidate.settimeout(0.2)
            usock_candidate = AEADDatagramSocket(raw_candidate, cipher_name=selected_cipher)
            deadline = time.time() + 8.0
            challenge_reply_sent = False
            last_hello_ts = 0.0
            while time.time() < deadline:
                now = time.time()
                if not challenge_reply_sent and (now - last_hello_ts) >= 0.2:
                    usock_candidate.send_plain(
                        mkp(
                            TYPE_HELLO,
                            payload=encode_transport_hello(
                                client_pub,
                                selected_cipher,
                                args.congestion_control,
                                args.cleartext,
                            ),
                        ).to_bytes(),
                        sockaddr,
                    )
                    last_hello_ts = now
                try:
                    raw, addr = usock_candidate.recvfrom(65535)
                except socket.timeout:
                    continue
                pkt = parse_packet(raw)
                if pkt is None or pkt.pkt_type != TYPE_HELLO:
                    continue
                if pkt.payload.startswith(CHALLENGE_PREFIX):
                    print(f"[DoU-CLIENT] received challenge from {addr[0]}:{addr[1]}")
                    rest = pkt.payload[len(CHALLENGE_PREFIX):]
                    parts = rest.split(b"\0", 5)
                    if len(parts) != 6 or len(parts[5]) != 32:
                        continue
                    token = parts[0].decode("ascii", "replace")
                    session_id = parts[1].decode("ascii", "replace")
                    session_cipher = parts[2].decode("ascii", "replace") or selected_cipher
                    negotiated_cc = parts[3].decode("ascii", "replace").removeprefix("cc=") or "off"
                    negotiated_cleartext = parts[4].decode("ascii", "replace").removeprefix("ct=") or "off"
                    server_pub = parts[5]
                    if session_cipher != selected_cipher:
                        raise SystemExit(f"server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}")
                    if negotiated_cleartext != args.cleartext:
                        raise SystemExit(f"server negotiated unexpected cleartext mode {negotiated_cleartext}; expected {args.cleartext}")
                    check_tofu(args.tofu_file, tofu_label, server_pub, allow_regen=args.regen_key)
                    reply = (
                        RESPONSE_PREFIX
                        + token.encode("ascii")
                        + b"\0"
                        + session_id.encode("ascii")
                        + b"\0"
                        + session_cipher.encode("ascii")
                        + b"\0cc="
                        + negotiated_cc.encode("ascii")
                        + b"\0ct="
                        + negotiated_cleartext.encode("ascii")
                        + b"\0"
                        + client_pub
                    )
                    usock_candidate.send_plain(mkp(TYPE_HELLO, payload=reply).to_bytes(), addr)
                    challenge_reply_sent = True
                    continue
                if pkt.payload.startswith(SESSION_PREFIX):
                    print(f"[DoU-CLIENT] received session from {addr[0]}:{addr[1]}")
                    rest = pkt.payload[len(SESSION_PREFIX):]
                    parts = rest.split(b"\0", 4)
                    if len(parts) != 5 or len(parts[4]) != 32:
                        continue
                    session_cipher = parts[1].decode("ascii", "replace") or selected_cipher
                    negotiated_cc = parts[2].decode("ascii", "replace").removeprefix("cc=") or "off"
                    negotiated_cleartext = parts[3].decode("ascii", "replace").removeprefix("ct=") or "off"
                    server_pub = parts[4]
                    if session_cipher != selected_cipher:
                        raise SystemExit(f"server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}")
                    if negotiated_cleartext != args.cleartext:
                        raise SystemExit(f"server negotiated unexpected cleartext mode {negotiated_cleartext}; expected {args.cleartext}")
                    check_tofu(args.tofu_file, tofu_label, server_pub, allow_regen=args.regen_key)
                    server_public = x25519.X25519PublicKey.from_public_bytes(server_pub)
                    session_key = derive_session_key(client_private.exchange(server_public), client_pub, server_pub)
                    usock_candidate.set_peer_psk(addr, session_key, session_cipher, cleartext=(negotiated_cleartext == "on"))
                    sender_candidate = USTPSender(
                        sock=usock_candidate,
                        peer=addr,
                        window=1024,
                        rto=0.20,
                        max_burst=1024,
                        pump_interval=0.0005,
                        congestion_control=(negotiated_cc == "on"),
                    )
                    sender_candidate.start()
                    raw_usock = raw_candidate
                    usock = usock_candidate
                    peer = addr
                    sender = sender_candidate
                    receiver = USTPReceiver(sock=usock_candidate, peer=addr)
                    print(f"[DoU-CLIENT] transport ready local={raw_candidate.getsockname()} peer={addr[0]}:{addr[1]}")
                    return
            raw_candidate.close()
        raise SystemExit("DoU server did not complete handshake")

    connect_transport()

    local_dns = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    tune_udp_socket(local_dns)
    try:
        local_dns.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    except OSError:
        pass
    local_dns.bind((args.local_dns_ip, args.local_dns_port, 0, 0))
    print(f"[DoU-CLIENT] local DNS listening on {args.local_dns_ip}:{args.local_dns_port}")

    def local_listener() -> None:
        while running:
            try:
                payload, src = local_dns.recvfrom(4096)
            except OSError:
                break
            request_id = next_request_id()
            with pending_lock:
                pending[request_id] = (src, time.time(), payload)
            print(f"[DoU-CLIENT] local dns query id={request_id} from={src[0]}:{src[1]} bytes={len(payload)}")
            try:
                sender.queue_payload(encode_frame(TYPE_QUERY, request_id, payload))
            except Exception as exc:
                with pending_lock:
                    pending.pop(request_id, None)
                servfail = build_dns_servfail(payload)
                if servfail is not None:
                    try:
                        local_dns.sendto(servfail, src)
                    except OSError:
                        pass
                print(f"[DoU-CLIENT] failed to queue local dns query id={request_id}: {exc}")

    def transport_listener() -> None:
        while running:
            try:
                raw, addr = usock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            pkt = parse_packet(raw)
            if pkt is None:
                continue
            if pkt.pkt_type in (TYPE_HELLO, TYPE_ACK, TYPE_RETRANSMIT_REQUEST):
                if pkt.pkt_type != TYPE_HELLO:
                    sender.on_control(pkt)
                continue
            if pkt.pkt_type == TYPE_CLOSE:
                print("[DoU-CLIENT] server closed the session")
                break
            if pkt.pkt_type != TYPE_DATA:
                continue
            payload = receiver.handle_data(pkt)
            receiver.maybe_nack()
            if not payload:
                continue
            frame = decode_frame(payload)
            if frame is None:
                continue
            request_id = frame["request_id"]
            if frame["type"] == TYPE_RESPONSE:
                with pending_lock:
                    info = pending.pop(request_id, None)
                if info is not None:
                    print(f"[DoU-CLIENT] local dns response id={request_id} to={info[0][0]}:{info[0][1]} bytes={len(frame['payload'])}")
                    local_dns.sendto(frame["payload"], info[0])
                continue
            if frame["type"] == TYPE_ERROR:
                info = decode_json_payload(frame["payload"]) or {}
                with pending_lock:
                    pending_info = pending.pop(request_id, None)
                if pending_info is not None:
                    servfail = build_dns_servfail(pending_info[2])
                    if servfail is not None:
                        try:
                            local_dns.sendto(servfail, pending_info[0])
                            print(f"[DoU-CLIENT] local dns upstream error id={request_id} -> SERVFAIL")
                        except OSError:
                            pass
                print(f"[DoU-CLIENT] request {request_id} failed: {info.get('message', 'unknown error')}")
                continue
            if frame["type"] == TYPE_PONG:
                continue

    def janitor() -> None:
        while running:
            now = time.time()
            stale = []
            with pending_lock:
                for request_id, (_, created_at, _) in pending.items():
                    if (now - created_at) > args.request_timeout:
                        stale.append(request_id)
                for request_id in stale:
                    info = pending.pop(request_id, None)
                    if info is None:
                        continue
                    servfail = build_dns_servfail(info[2])
                    if servfail is not None:
                        try:
                            local_dns.sendto(servfail, info[0])
                            print(f"[DoU-CLIENT] local dns timeout id={request_id} -> SERVFAIL")
                        except OSError:
                            pass
            time.sleep(0.25)

    local_thread = threading.Thread(target=local_listener, daemon=True)
    transport_thread = threading.Thread(target=transport_listener, daemon=True)
    janitor_thread = threading.Thread(target=janitor, daemon=True)

    local_thread.start()
    transport_thread.start()
    janitor_thread.start()

    try:
        while transport_thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        running = False
        try:
            sender.queue_payload(encode_frame(TYPE_PING, 0, b"bye"))
        except Exception:
            pass
        try:
            usock.send_plain(mkp(TYPE_CLOSE, payload=b"BYE").to_bytes(), peer)
        except Exception:
            pass
        try:
            local_dns.close()
        except Exception:
            pass
        try:
            if sender is not None:
                sender.stop()
        except Exception:
            pass
        try:
            if raw_usock is not None:
                raw_usock.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
