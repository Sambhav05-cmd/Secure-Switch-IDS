"""
block_agent.py  —  Snort alert → SDN block agent
=================================================
Reads /var/log/snort/alert (tail -f style).
For each alert, writes "BLOCK <ip>" to the named pipe /tmp/block_pipe,
which simple_switch_13 reads and converts into an OpenFlow DROP flow.

No REST API required. Works with any version of os-ken.
"""

import os
import re
import time
import threading
import logging

ALERT_FILE         = os.environ.get("SNORT_ALERT_FILE", "/var/log/snort/alert")
PIPE_PATH          = "/tmp/block_pipe"
BLOCK_TIMEOUT      = int(os.environ.get("BLOCK_TIMEOUT_SECONDS", "0"))  # 0 = permanent
WHITELIST          = set(os.environ.get("WHITELIST_IPS", "").split(",")) - {""}
POLL_INTERVAL      = 0.3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("block_agent")

BLOCKED: dict = {}   # {src_ip: blocked_at_timestamp}
_lock = threading.Lock()

# Matches Snort fast-alert lines:
#   MM/DD-HH:MM:SS.us [**] [sid] msg [**] {PROTO} src_ip[:port] -> dst_ip[:port]
_ALERT_RE = re.compile(
    r"\[\*\*\]\s+\[[\d:]+\]\s+(?P<msg>.+?)\s+\[\*\*\]"
    r".*?\{(?P<proto>TCP|UDP|ICMP)\}\s+"
    r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)"
)


def parse_alert(line):
    m = _ALERT_RE.search(line)
    if m:
        return m.group("src_ip"), m.group("msg").strip()
    return None, None


def write_to_pipe(command):
    """Write a BLOCK/UNBLOCK command to the named pipe (non-blocking open with retry)."""
    for attempt in range(5):
        try:
            # Open in non-blocking mode — fails immediately if no reader
            fd = os.open(PIPE_PATH, os.O_WRONLY | os.O_NONBLOCK)
            with os.fdopen(fd, "w") as pipe:
                pipe.write(command + "\n")
                pipe.flush()
            return True
        except OSError:
            time.sleep(1)
    log.error("Could not write to pipe after 5 attempts: %s", command)
    return False


def wait_for_pipe():
    log.info("Waiting for named pipe %s to be created by controller ...", PIPE_PATH)
    while not os.path.exists(PIPE_PATH):
        time.sleep(1)
    log.info("Pipe found: %s", PIPE_PATH)


def block_ip(src_ip, reason):
    with _lock:
        if src_ip in BLOCKED:
            return
        if src_ip in WHITELIST:
            log.info("WHITELIST  %-16s (reason: %s)", src_ip, reason)
            return

        log.warning("BLOCKING   %-16s  reason: %s", src_ip, reason)
        if write_to_pipe(f"BLOCK {src_ip}"):
            BLOCKED[src_ip] = time.time()
            log.info("PIPE_SENT  BLOCK %-16s", src_ip)
            if BLOCK_TIMEOUT > 0:
                t = threading.Timer(BLOCK_TIMEOUT, unblock_ip, args=(src_ip,))
                t.daemon = True
                t.start()
                log.info("UNBLOCK_IN %-16s  in %ds", src_ip, BLOCK_TIMEOUT)


def unblock_ip(src_ip):
    with _lock:
        if src_ip not in BLOCKED:
            return
        if write_to_pipe(f"UNBLOCK {src_ip}"):
            del BLOCKED[src_ip]
            log.info("UNBLOCKED  %-16s", src_ip)


def wait_for_alert_file():
    if not os.path.exists(ALERT_FILE):
        log.info("Waiting for alert file: %s", ALERT_FILE)
        while not os.path.exists(ALERT_FILE):
            time.sleep(1)
    log.info("Alert file ready: %s", ALERT_FILE)


def tail_alerts():
    wait_for_alert_file()
    log.info("Tailing %s", ALERT_FILE)

    fh = open(ALERT_FILE, "r")
    fh.seek(0, 2)  # skip old alerts
    current_inode = os.fstat(fh.fileno()).st_ino

    while True:
        line = fh.readline()
        if line:
            line = line.rstrip()
            if line:
                src_ip, reason = parse_alert(line)
                if src_ip:
                    log.info("ALERT      %-16s  %s", src_ip, reason)
                    block_ip(src_ip, reason)
        else:
            # Handle log rotation
            try:
                if os.stat(ALERT_FILE).st_ino != current_inode:
                    log.info("Log rotation — reopening %s", ALERT_FILE)
                    fh.close()
                    fh = open(ALERT_FILE, "r")
                    current_inode = os.fstat(fh.fileno()).st_ino
            except FileNotFoundError:
                pass
            time.sleep(POLL_INTERVAL)


def status_reporter():
    while True:
        time.sleep(30)
        with _lock:
            count = len(BLOCKED)
        log.info("STATUS  %d IP(s) blocked: %s",
                 count, ", ".join(BLOCKED.keys()) if BLOCKED else "(none)")


def main():
    log.info("=== block_agent starting ===")
    log.info("  ALERT_FILE     = %s", ALERT_FILE)
    log.info("  PIPE_PATH      = %s", PIPE_PATH)
    log.info("  BLOCK_TIMEOUT  = %s", f"{BLOCK_TIMEOUT}s" if BLOCK_TIMEOUT else "permanent")
    log.info("  WHITELIST      = %s", WHITELIST or "(none)")

    wait_for_pipe()

    threading.Thread(target=status_reporter, daemon=True).start()

    tail_alerts()


if __name__ == "__main__":
    main()
