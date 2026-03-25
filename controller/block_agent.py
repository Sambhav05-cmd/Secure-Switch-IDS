import time
import re
import requests

ALERT_FILE = '/var/log/snort/alert'
OSKEN_REST  = 'http://os-ken-ctrl:8080'
DPID        = None   # will be fetched dynamically
BLOCKED_IPS = set()

def get_dpid():
    """Get the first switch DPID from os-ken REST API"""
    r = requests.get(f'{OSKEN_REST}/stats/switches')
    switches = r.json()
    if switches:
        return switches[0]
    return None

def block_ip(dpid, src_ip):
    """Install a DROP flow for src_ip on the switch"""
    if src_ip in BLOCKED_IPS:
        return
    print(f"[!] Blocking IP: {src_ip}", flush=True)

    flow = {
        "dpid": dpid,
        "priority": 100,          # higher than table-miss (0) and learned flows (1)
        "match": {
            "ipv4_src": src_ip,
            "eth_type": 2048       # IPv4
        },
        "actions": []              # empty actions = DROP
    }

    r = requests.post(f'{OSKEN_REST}/stats/flowentry/add', json=flow)
    if r.status_code == 200:
        BLOCKED_IPS.add(src_ip)
        print(f"[✔] Flow installed to DROP {src_ip}", flush=True)
    else:
        print(f"[✘] Failed to block {src_ip}: {r.text}", flush=True)

def parse_alert_line(line):
    """Extract source IP from snort fast alert format"""
    # Format: MM/DD-HH:MM:SS.us [**] [sid] msg [**] {PROTO} src_ip:port -> dst_ip:port
    match = re.search(r'\{(?:TCP|UDP|ICMP)\}\s+(\d+\.\d+\.\d+\.\d+)', line)
    if match:
        return match.group(1)
    return None

def tail_alerts():
    """Tail the snort alert file and react to new alerts"""
    print("[*] block_agent watching /var/log/snort/alert ...", flush=True)

    global DPID
    while DPID is None:
        try:
            DPID = get_dpid()
            print(f"[*] Got DPID: {DPID}", flush=True)
        except Exception:
            print("[*] Waiting for os-ken REST API...", flush=True)
            time.sleep(2)

    # Open and tail the alert file
    with open(ALERT_FILE, 'r') as f:
        f.seek(0, 2)  # seek to end
        while True:
            line = f.readline()
            if line:
                src_ip = parse_alert_line(line.strip())
                if src_ip:
                    print(f"[!] Alert: {line.strip()}", flush=True)
                    block_ip(DPID, src_ip)
            else:
                time.sleep(0.5)

if __name__ == '__main__':
    tail_alerts()