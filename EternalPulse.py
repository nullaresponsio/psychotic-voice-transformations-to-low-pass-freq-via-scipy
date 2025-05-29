#!/usr/bin/env python3
# ultimate_test.py

import argparse, logging, socket, subprocess, requests, json, concurrent.futures, ssl, platform, select, struct, re
from impacket.smbconnection import SMBConnection

# ---------- Service helpers ----------

def probe_smb(host: str, port: int):
    # Connect to SMB, login anonymously, return protocol dialect and whether signing is required
    smb = SMBConnection(remoteName=host, remoteHost=host, sess_port=port)
    smb.login('', '')
    d, s = smb.getDialect(), smb.isSigningRequired()
    smb.close()
    return d, s

def icmp_ping(host: str, timeout: int):
    # Send one ICMP echo request; Windows uses -n/-w, others -c/-W
    cmd = ["ping", "-n", "1", "-w", str(timeout*1000), host] if platform.system().lower() == 'windows' \
          else ["ping", "-c", "1", "-W", str(timeout), host]
    return subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def tcp_connect(host: str, port: int, timeout: int):
    # Attempt a TCP handshake, return True if successful
    try:
        s = socket.create_connection((host, port), timeout)
        s.close()
        return True
    except Exception:
        return False

def udp_probe(host: str, port: int, timeout: int):
    # Send empty UDP datagram and wait for a response or timeout
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'', (host, port))
        sock.recvfrom(1024)
        sock.close()
        return True
    except Exception:
        return False

def http_probe(host: str, port: int, timeout: int):
    # Perform HTTP GET, return status code and Server header
    try:
        r = requests.get(f"http://{host}:{port}", timeout=timeout)
        return {"code": r.status_code, "server": r.headers.get("Server", "")}
    except Exception as e:
        return {"error": str(e)}

def https_probe(host: str, port: int, timeout: int):
    # Open SSL connection, retrieve certificate issuer and subject
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            cert = s.getpeercert()
        return {"issuer": cert.get("issuer"), "subject": cert.get("subject")}
    except Exception as e:
        return {"error": str(e)}

# ---------- CVE checks ----------

def assess_smb_cves(dialect: int, signing: bool):
    # Map SMB dialect/signing to known CVEs
    r = []
    if dialect == 1:
        r.append("CVE-2017-0144")
    if dialect == 3 and not signing:
        r.append("CVE-2020-0796")
    return r

def heartbleed_check(host: str, port: int, timeout: int):
    # Send TLS heartbeat and check for excess data leakage
    hello  = bytes.fromhex(
        "16 03 02 00 dc 01 00 00 d8 03 02 53 43 5b 90" + " 00"*104
    )
    hb_req = bytes.fromhex("18 03 02 00 03 01 40 00")
    try:
        s = socket.create_connection((host, port), timeout)
        s.sendall(hello)
        _ = s.recv(4096)
        s.sendall(hb_req)
        if select.select([s], [], [], timeout)[0] and s.recv(4096):
            s.close()
            return True
        s.close()
    except Exception:
        pass
    return False

def bluekeep_check(host: str, port: int, timeout: int):
    # Send RDP packet and inspect response byte for vulnerability indicator
    pkt = bytes.fromhex("030000130ed0000012340006d0000000000000")
    try:
        s = socket.create_connection((host, port), timeout)
        s.sendall(pkt)
        resp = s.recv(1024)
        s.close()
        if len(resp) >= 12 and resp[11] == 0:
            return True
    except Exception:
        pass
    return False

def openssh_enum_check(host: str, port: int, timeout: int):
    # Read SSH banner, detect OpenSSH versions older than 7.7
    try:
        s = socket.create_connection((host, port), timeout)
        banner = s.recv(256).decode(errors='ignore')
        s.close()
        m = re.search(r'OpenSSH_(\d+\.\d+)', banner)
        if m and float(m.group(1)) < 7.7:
            return True
    except Exception:
        pass
    return False

def httpsys_range_check(host: str, port: int, timeout: int):
    # Send oversized byte-range header, look for HTTP 416 with Microsoft in response
    req = (f"GET / HTTP/1.1\r\nHost: {host}\r\nRange: bytes=0-18446744073709551615\r\n\r\n").encode()
    try:
        s = socket.create_connection((host, port), timeout)
        s.sendall(req)
        resp = s.recv(1024).decode(errors='ignore')
        s.close()
        if resp.startswith("HTTP/1.1 416") and "Microsoft" in resp:
            return True
    except Exception:
        pass
    return False

# List of additional CVE tests with target ports and functions
CVE_CHECKS = [
    ("CVE-2019-0708", [3389], bluekeep_check),
    ("CVE-2018-15473", [22], openssh_enum_check),
    ("CVE-2015-1635", [80, 8080], httpsys_range_check),
]

# ---------- Comprehensive ----------

def comprehensive_test(host: str, tcp_ports, udp_ports, timeout: int):
    # Run all probes and CVE checks, aggregate results
    res = {"icmp": icmp_ping(host, timeout), "tcp": {}, "udp": {}, "http": {}, "https": {}, "cve": []}

    # Parallel TCP connect scans
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(tcp_connect, host, p, timeout): p for p in tcp_ports}
        for f in concurrent.futures.as_completed(futs):
            res["tcp"][futs[f]] = f.result()

    # Sequential UDP probes
    for p in udp_ports:
        res["udp"][p] = udp_probe(host, p, timeout)

    # Service-specific tests on open TCP ports
    for p in tcp_ports:
        if p in (80, 8080):
            res["http"][p] = http_probe(host, p, timeout)
        if p == 443:
            res["https"][p] = https_probe(host, p, timeout)
            if heartbleed_check(host, p, timeout):
                res["cve"].append("CVE-2014-0160")
        if p == 445 and res["tcp"].get(p):
            try:
                d, sgn = probe_smb(host, p)
                res["cve"].extend(assess_smb_cves(d, sgn))
            except Exception:
                pass

    # Run additional CVE checks on relevant ports
    open_tcp = [p for p, ok in res["tcp"].items() if ok]
    for cve_id, ports, fn in CVE_CHECKS:
        if any(p in open_tcp for p in ports):
            for p in ports:
                if p in open_tcp and fn(host, p, timeout):
                    res["cve"].append(cve_id)
                    break

    res["cve"] = sorted(set(res["cve"]))
    return res

# ---------- CLI ----------

def main():
    # Parse arguments, configure logging, run comprehensive_test, print JSON or dict
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True)
    p.add_argument("--tcp-ports", default="80,443,22,25,53,8080,445,3389")
    p.add_argument("--udp-ports", default="53")
    p.add_argument("--timeout", type=int, default=2)
    p.add_argument("--json", action="store_true")
    a = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    tcp_ports = [int(x) for x in a.tcp_ports.split(',') if x]
    udp_ports = [int(x) for x in a.udp_ports.split(',') if x]
    res = comprehensive_test(a.host, tcp_ports, udp_ports, a.timeout)
    print(json.dumps(res, indent=2) if a.json else res)

if __name__ == "__main__":
    main()

# -----------------------------------------------------------------------------
# Summary & Recommendations for Future CVE Testing Optimization
#
# 1. Modularize CVE Definitions:
#    - Store CVE metadata (ID, ports, detection function, protocol specifics) in
#      a structured config (e.g., YAML/JSON). Enables adding new tests without code changes.
#
# 2. Enhance Parallelism and Resource Management:
#    - Use async IO (asyncio) for network probes to reduce thread overhead.
#    - Implement rate limiting and dynamic timeouts based on historical response times.
#
# 3. Improve Detection Reliability:
#    - Integrate protocol-specific libraries (e.g., TLS libraries for heartbleed),
#      reducing custom packet crafting and parsing errors.
#    - Add sanity checks and fallback mechanisms when receiving malformed or no responses.
#
# 4. Reporting & Logging:
#    - Centralize logging with per-test verbosity levels; output structured logs (JSON)
#      for easy ingestion into SIEM or dashboards.
#    - Record timing metrics to identify slow or problematic checks.
#
# 5. CVE Test Coverage & Maintenance:
#    - Automate regular updates from vulnerability databases (e.g., NVD) to pull new CVEs.
#    - Provide CI pipeline integration that validates new CVE tests against a test lab.
#
# 6. Security & Isolation:
#    - Run tests in isolated containers or sandboxes to prevent accidental damage.
#    - Validate inputs to avoid injection via hostnames or port lists.
#
# 7. Scalability & Extensibility:
#    - Abstract transport layer to plug in new protocols (e.g., QUIC, HTTP/2).
#    - Provide plugin interfaces for community-contributed CVE checks.
#
# By applying these practices, the testing framework will adapt more quickly
# to emerging threats, maintain higher accuracy, and scale to enterprise needs.
