#!/usr/bin/env python3
import argparse
import sys
import yaml
import re
from getpass import getpass
from datetime import datetime
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoAuthenticationException, NetMikoTimeoutException

# ----- Simple thresholds -----
GREEN_MAX = 0.60   # <60% = green
ORANGE_MAX = 0.80  # 60-80% = orange; >80% = red
MISMATCH_TOL = 0.02  # 2% mismatch triggers amber row

# ----- HTML templates -----
HTML = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>{title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
body {{ padding:20px; }}
.mono {{ font-family: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace; }}
.util-green {{ background-color:#d4edda !important; }}
.util-orange{{ background-color:#ffe5b4 !important; }}
.util-red {{ background-color:#f8d7da !important; }}
.cap-mismatch {{ background-color:#ffecb5 !important; }}
.smallnote {{ color:#555; }}
</style></head>
<body>
<h1 class="mb-2">{title}</h1>
<div class="smallnote mb-3">Generated: {generated} • Peer: <strong>{peer}</strong> • Devices: {devcount}</div>
<div class="accordion" id="accordion">{sections}</div>
<hr class="my-4">
<div class="small">
  <span class="badge text-bg-success">Util &lt; 60%</span>
  <span class="badge text-bg-warning">60–80%</span>
  <span class="badge text-bg-danger">Util &gt; 80%</span>
  &nbsp;|&nbsp;<span class="badge" style="background:#ffecb5">Configured vs Available mismatch</span>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
"""

DEVICE = """
<div class="accordion-item">
  <h2 class="accordion-header" id="h-{sid}">
    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#c-{sid}">
      {name} <span class="ms-2 badge text-bg-secondary">{platform}</span>
      <span class="ms-2 text-muted small">({count} LAGs)</span>
    </button>
  </h2>
  <div id="c-{sid}" class="accordion-collapse collapse"><div class="accordion-body">{table}</div></div>
</div>
"""

TABLE = """
<div class="table-responsive">
<table class="table table-sm table-bordered align-middle">
  <thead class="table-light"><tr>
    <th>Interface</th><th class="mono">Description</th>
    <th>Configured</th><th>Available</th>
    <th>Max Input</th><th>Utilization</th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>
</div>
"""

ROW = """
<tr class="{rowcls}">
  <td class="mono">{ifname}</td>
  <td class="mono">{desc}</td>
  <td>{conf}</td><td>{avail}</td>
  <td>{maxin}</td><td class="{utilcls}">{util}</td>
</tr>
"""

# ----- Helpers -----
def human_bps(bps):
    if bps is None:
        return "—"
    units = [("Tbps",1e12), ("Gbps",1e9), ("Mbps",1e6), ("Kbps",1e3), ("bps",1)]
    for name, factor in units:
        if bps >= factor:
            v = bps / factor
            return f"{int(v):,} {name}" if name == "bps" else f"{v:.2f} {name}"
    return f"{bps:.0f} bps"

def classify_util(util):
    if util is None:
        return ("", "—")
    pct = util * 100.0
    if pct < GREEN_MAX * 100:
        return ("util-green", f"{pct:.1f}%")
    elif pct <= ORANGE_MAX * 100:
        return ("util-orange", f"{pct:.1f}%")
    else:
        return ("util-red", f"{pct:.1f}%")

def capacity_mismatch(conf_bps, avail_bps):
    if not conf_bps or not avail_bps:
        return False
    return abs(conf_bps - avail_bps) / max(conf_bps, avail_bps) > MISMATCH_TOL

def sid(text):
    return re.sub(r"[^a-zA-Z0-9_-]", "_", text)

# ----- Cisco XR parser (Bundle-Ether only) -----
def parse_cisco_xr(output: str, peer: str):
    rows = []
    # Split stanzas starting with Bundle-Ether... is up
    blocks = re.split(r"(?=^Bundle-Ether[^\n]* is up, line protocol is)", output, flags=re.M)
    for blk in blocks:
        if not blk.strip():
            continue

        # Interface name
        m_if = re.search(r"^(Bundle-Ether\S+)", blk, re.M)
        if not m_if:
            continue
        ifname = m_if.group(1)

        # Description line
        m_desc = re.search(r"^\s*Description:\s*(.+)$", blk, re.M)
        desc = m_desc.group(1).strip() if m_desc else ""

        # Must contain [NAME=<peer>] (case-insensitive)
        if not re.search(rf"\[NAME={re.escape(peer)}\]", desc, re.I):
            continue

        # Configured capacity from [BW=###G] in description
        m_bwdesc = re.search(r"\[BW=(\d+(?:\.\d+)?)\s*G\]", desc, re.I)
        conf_bps = float(m_bwdesc.group(1))*1e9 if m_bwdesc else None

        # Available capacity from "BW <num> Kbit"
        m_av = re.search(r"\bBW\s+(\d+)\s*Kbit", blk)
        avail_bps = float(m_av.group(1))*1e3 if m_av else None

        # Max input from "30 second input rate <num> bits/sec"
        m_in = re.search(r"30 second input rate\s+(\d+)\s+bits/sec", blk, re.I)
        max_in_bps = float(m_in.group(1)) if m_in else None

        util = (max_in_bps/avail_bps) if (max_in_bps and avail_bps) else None

        rows.append({
            "ifname": ifname,
            "desc": desc,
            "conf_bps": conf_bps,
            "avail_bps": avail_bps,
            "max_input_bps": max_in_bps,
            "util": util
        })
    return rows

# ----- HTML builders -----
def device_table(rows):
    row_html = []
    for r in rows:
        utilcls, utilstr = classify_util(r["util"])
        rowcls = "cap-mismatch" if capacity_mismatch(r["conf_bps"], r["avail_bps"]) else ""
        row_html.append(ROW.format(
            rowcls=rowcls,
            ifname=r["ifname"],
            desc=r["desc"],
            conf=human_bps(r["conf_bps"]),
            avail=human_bps(r["avail_bps"]),
            maxin=human_bps(r["max_input_bps"]),
            utilcls=utilcls,
            util=utilstr
        ))
    return TABLE.format(rows="".join(row_html) if row_html else '<tr><td colspan="6" class="text-muted">No matching LAGs.</td></tr>')

def device_section(name, rows):
    return DEVICE.format(sid=sid(name), name=name, platform="cisco_xr", count=len(rows), table=device_table(rows))

def build_html(peer, sections):
    title = f"LAG Capacity & Utilization — {peer} (Cisco only)"
    return HTML.format(
        title=title,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        peer=peer,
        devcount=len(sections),
        sections="".join(sections)
    )

# ----- Connect & collect -----
def collect_device(host, username, password, peer):
    params = {
        "device_type": "cisco_xr",
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": True
    }
    cmd = "show interfaces Bundle-Ether | no-more"
    try:
        conn = ConnectHandler(**params)
        out = conn.send_command(cmd, expect_string=None, read_timeout=90)
        conn.disconnect()
    except NetMikoAuthenticationException as e:
        return [], [f"{host}: auth failed: {e}"]
    except NetMikoTimeoutException as e:
        return [], [f"{host}: timeout: {e}"]
    except Exception as e:
        return [], [f"{host}: command error: {e}"]

    try:
        rows = parse_cisco_xr(out, peer)
        return rows, []
    except Exception as e:
        return [], [f"{host}: parse error: {e}"]

# ----- CLI -----
def main():
    ap = argparse.ArgumentParser(description="Cisco-only LAG report by peer")
    ap.add_argument("--peer", required=True, help="AMAZON / NETFLIX / GOOGLE ...")
    ap.add_argument("--inventory", required=True, help="Path to inventory.yml")
    ap.add_argument("--output", default=None, help="Output HTML (default: peer_report_<PEER>_cisco.html)")
    args = ap.parse_args()

    # Load inventory
    try:
        with open(args.inventory, "r") as f:
            inv = yaml.safe_load(f)
    except Exception as e:
        print(f"Failed to read inventory: {e}", file=sys.stderr)
        sys.exit(2)

    if "peers" not in inv or args.peer not in inv["peers"]:
        print(f"Peer '{args.peer}' not found in inventory", file=sys.stderr)
        sys.exit(2)
    devices = inv["peers"][args.peer]
    if not devices:
        print(f"No devices listed for peer '{args.peer}'", file=sys.stderr)
        sys.exit(2)

    username = input("Username: ").strip()
    password = getpass("Password: ")

    sections = []
    for dev in devices:
        host = dev["host"]
        # ignore non-cisco entries silently in this Cisco-only MVP
        if str(dev.get("device_type","")).lower() not in ("cisco_xr","iosxr","cisco-iosxr"):
            continue
        rows, errs = collect_device(host, username, password, args.peer)
        # show errors inline as a single-row table if any
        if errs and not rows:
            err_rows = [{
                "ifname": "—",
                "desc": "; ".join(errs),
                "conf_bps": None,
                "avail_bps": None,
                "max_input_bps": None,
                "util": None
            }]
            sections.append(device_section(host, err_rows))
        else:
            sections.append(device_section(host, rows))

    html = build_html(args.peer, sections)
    outpath = args.output or f"peer_report_{args.peer}_cisco.html"
    with open(outpath, "w", encoding="utf-8") as fh:
        fh.write(html)

    print(f"Report written to: {outpath}")

if __name__ == "__main__":
    main()
