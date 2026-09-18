#!/usr/bin/env python3
"""
Windows Event Log Analyser
---------------------------
Detects failed logon attempts (Event ID 4625) and highlights suspicious
source IPs using configurable thresholds.

Supports two input formats:
- Text-exported Windows Security logs (.log / .txt)
- Real Windows .evtx files (requires: pip install python-evtx)

Exports: terminal report + CSV + JSON + HTML

Features:
- Interactive mode (beginner-friendly) and command-line mode (for automation)
- Colored terminal output
- Two-tier alert thresholds (Suspicious / Critical)
"""

import re
import csv
import json
import argparse
import sys
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple


# ====================== CONFIG ======================
DEFAULT_THRESHOLD = 5   # ≥ this many failed attempts = SUSPICIOUS
DEFAULT_CRITICAL = 15   # ≥ this many failed attempts = CRITICAL
# ====================================================


class Colors:
    """ANSI color codes (work on most modern terminals)."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"


def color(text: str, color_code: str) -> str:
    """Wrap text in an ANSI color code, but only if stdout is a real terminal."""
    if sys.stdout.isatty():
        return f"{color_code}{text}{Colors.RESET}"
    return text


def parse_text_log(file_path: str) -> Tuple[Counter, Counter, Dict]:
    """Parse text-exported Windows Security logs (Event ID 4625)"""
    pattern = re.compile(
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?'
        r'EventID\s*=\s*4625.*?'
        r'Account Name:\s*(?P<user>\S+).*?'
        r'Source Network Address:\s*(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?'
        r'Logon Type:\s*(?P<logon_type>\d+).*?'
        r'Failure Reason:\s*(?P<reason>.*?)(?:\s*$|\s+Process)',
        re.IGNORECASE
    )

    ip_counter = Counter()
    user_counter = Counter()
    details = defaultdict(list)

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            if 'EventID=4625' not in line and 'EventID = 4625' not in line:
                continue

            match = pattern.search(line)
            if match:
                data = match.groupdict()
                ip = data['ip']
                user = data['user']
                ip_counter[ip] += 1
                user_counter[user] += 1
                details[ip].append({
                    'timestamp': data['timestamp'],
                    'username': user,
                    'logon_type': data.get('logon_type', '?'),
                    'reason': data.get('reason', 'Unknown').strip(),
                    'line': line_num
                })
            else:
                ip_match = re.search(r'Source Network Address:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                user_match = re.search(r'Account Name:\s*(\S+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    user = user_match.group(1) if user_match else 'unknown'
                    ip_counter[ip] += 1
                    user_counter[user] += 1
                    details[ip].append({
                        'timestamp': 'N/A',
                        'username': user,
                        'logon_type': '?',
                        'reason': 'Failed logon',
                        'line': line_num
                    })

    return ip_counter, user_counter, details


def parse_evtx_log(file_path: str) -> Tuple[Counter, Counter, Dict]:
    """Parse real Windows .evtx files (requires python-evtx)"""
    try:
        import Evtx.Evtx as evtx
    except ImportError:
        print(color("\n❌ Missing library: python-evtx", Colors.RED))
        print("   Install it with:  pip install python-evtx")
        print("   Then run the script again.\n")
        sys.exit(1)

    ip_counter = Counter()
    user_counter = Counter()
    details = defaultdict(list)

    print(color("   Reading .evtx file (this can take a moment)...", Colors.GRAY))

    with evtx.Evtx(file_path) as log:
        for record in log.records():
            try:
                xml = record.xml()
            except Exception:
                continue

            if "<EventID>4625</EventID>" not in xml and "<EventID Qualifiers=\"0\">4625</EventID>" not in xml:
                continue

            ip_match = re.search(r'<Data Name="IpAddress">([^<]+)</Data>', xml)
            user_match = re.search(r'<Data Name="TargetUserName">([^<]+)</Data>', xml)
            logon_type_match = re.search(r'<Data Name="LogonType">([^<]+)</Data>', xml)
            status_match = re.search(r'<Data Name="Status">([^<]+)</Data>', xml)
            time_match = re.search(r'SystemTime="([^"]+)"', xml)

            ip = ip_match.group(1).strip() if ip_match else None
            user = user_match.group(1).strip() if user_match else "unknown"
            logon_type = logon_type_match.group(1).strip() if logon_type_match else "?"
            reason = status_match.group(1).strip() if status_match else "Failed logon"
            timestamp = time_match.group(1)[:19].replace("T", " ") if time_match else "N/A"

            if not ip or ip in ("-", "::1", "127.0.0.1", ""):
                continue

            ip_counter[ip] += 1
            user_counter[user] += 1
            details[ip].append({
                'timestamp': timestamp,
                'username': user,
                'logon_type': logon_type,
                'reason': reason,
                'line': record.record_num()
            })

    return ip_counter, user_counter, details


def parse_log(file_path: str) -> Tuple[Counter, Counter, Dict]:
    """Auto-detect file type and parse accordingly"""
    path = Path(file_path)

    if path.suffix.lower() == ".evtx":
        print(color("   Detected real Windows .evtx file", Colors.CYAN))
        return parse_evtx_log(file_path)
    else:
        print(color("   Detected text log file", Colors.CYAN))
        return parse_text_log(file_path)


def get_severity(count: int, threshold: int, critical: int) -> str:
    """Classify a failed-attempt count as LOW / SUSPICIOUS / CRITICAL."""
    if count >= critical:
        return "CRITICAL"
    elif count >= threshold:
        return "SUSPICIOUS"
    return "LOW"


def severity_colored(severity: str) -> str:
    """Return a severity label wrapped in its matching terminal color."""
    if severity == "CRITICAL":
        return color("CRITICAL", Colors.RED + Colors.BOLD)
    elif severity == "SUSPICIOUS":
        return color("SUSPICIOUS", Colors.YELLOW + Colors.BOLD)
    return color("LOW", Colors.GREEN)


def print_terminal_report(ip_counter: Counter, user_counter: Counter,
                           details: Dict, threshold: int, critical: int) -> None:
    """Print the full colored summary report to the terminal."""
    total_failures = sum(ip_counter.values())
    unique_ips = len(ip_counter)
    unique_users = len(user_counter)

    print()
    print(color("=" * 70, Colors.CYAN))
    print(color(" WINDOWS EVENT LOG ANALYSER - Failed Logon Report (Event ID 4625)", Colors.BOLD))
    print(color("=" * 70, Colors.CYAN))
    print(f" Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Thresholds : ≥{threshold} = SUSPICIOUS  |  ≥{critical} = CRITICAL")
    print(color("-" * 70, Colors.GRAY))
    print(f" Total failed logons   : {color(str(total_failures), Colors.BOLD)}")
    print(f" Unique source IPs     : {unique_ips}")
    print(f" Unique targeted users : {unique_users}")
    print(color("=" * 70, Colors.CYAN))

    # Top IPs table
    print()
    print(color("TOP SOURCE IPs (Failed Logon Attempts)", Colors.BOLD + Colors.BLUE))
    print(color("─" * 65, Colors.GRAY))
    print(f"{'IP Address':<18} {'Count':>7}   {'Severity'}")
    print(color("─" * 65, Colors.GRAY))

    for ip, count in ip_counter.most_common(20):
        severity = get_severity(count, threshold, critical)
        sev_text = severity_colored(severity)
        flag = ""
        if severity == "CRITICAL":
            flag = color(" 🔥", Colors.RED)
        elif severity == "SUSPICIOUS":
            flag = color(" ⚠️", Colors.YELLOW)
        print(f"{ip:<18} {count:>7}   {sev_text}{flag}")

    print(color("─" * 65, Colors.GRAY))

    # Top usernames
    print()
    print(color("MOST TARGETED USERNAMES", Colors.BOLD + Colors.BLUE))
    print(color("─" * 40, Colors.GRAY))
    print(f"{'Username':<22} {'Attempts':>8}")
    print(color("─" * 40, Colors.GRAY))
    for user, count in user_counter.most_common(12):
        print(f"{user:<22} {count:>8}")
    print(color("─" * 40, Colors.GRAY))

    # Detailed high-risk IPs
    high_risk = [(ip, count) for ip, count in ip_counter.most_common() if count >= threshold]

    if high_risk:
        print()
        print(color("=" * 70, Colors.CYAN))
        print(color(" DETAILED VIEW – High Risk / Suspicious IPs", Colors.BOLD))
        print(color("=" * 70, Colors.CYAN))

        for ip, count in high_risk:
            severity = get_severity(count, threshold, critical)
            sev_text = severity_colored(severity)
            print()
            print(f"{color('▶', Colors.CYAN)} {color(ip, Colors.BOLD)}  →  {count} failed attempts  [{sev_text}]")
            print(color("─" * 60, Colors.GRAY))
            for entry in details[ip][:6]:
                print(f"   {entry['timestamp']:<20} | User: {entry['username']:<18} "
                      f"| Type: {entry['logon_type']} | {entry['reason']}")
            if len(details[ip]) > 6:
                print(color(f"   ... and {len(details[ip]) - 6} more attempts", Colors.GRAY))
    else:
        print()
        print(color("✅ No IPs exceeded the suspicious threshold.", Colors.GREEN))

    print()
    print(color("=" * 70, Colors.CYAN))


def export_csv(ip_counter: Counter, details: Dict, output_path: str,
                threshold: int, critical: int) -> None:
    """Write a one-row-per-IP summary CSV report."""
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['IP Address', 'Failed Attempts', 'Severity',
                         'Most Targeted User', 'First Seen', 'Last Seen'])
        for ip, count in ip_counter.most_common():
            severity = get_severity(count, threshold, critical)
            users = [e['username'] for e in details[ip]]
            most_common_user = Counter(users).most_common(1)[0][0] if users else 'N/A'
            timestamps = [e['timestamp'] for e in details[ip] if e['timestamp'] != 'N/A']
            first = timestamps[0] if timestamps else 'N/A'
            last = timestamps[-1] if timestamps else 'N/A'
            writer.writerow([ip, count, severity, most_common_user, first, last])
    print(color(f"✅ CSV  → {output_path}", Colors.GREEN))


def export_json(ip_counter: Counter, user_counter: Counter, details: Dict,
                 output_path: str, threshold: int, critical: int) -> None:
    """Write a full machine-readable JSON report, including per-attempt detail."""
    report = {
        'generated_at': datetime.now().isoformat(),
        'thresholds': {'suspicious': threshold, 'critical': critical},
        'summary': {
            'total_failed_logons': sum(ip_counter.values()),
            'unique_ips': len(ip_counter),
            'unique_users': len(user_counter)
        },
        'top_ips': [
            {'ip': ip, 'count': count,
             'severity': get_severity(count, threshold, critical),
             'attempts': details[ip]}
            for ip, count in ip_counter.most_common()
        ],
        'top_users': [{'username': u, 'count': c} for u, c in user_counter.most_common()]
    }
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(color(f"✅ JSON → {output_path}", Colors.GREEN))


def export_html(ip_counter: Counter, user_counter: Counter, details: Dict,
                 output_path: str, threshold: int, critical: int) -> None:
    """Write a self-contained, styled HTML report."""
    total = sum(ip_counter.values())
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    rows = ""
    for ip, count in ip_counter.most_common():
        severity = get_severity(count, threshold, critical)
        css = severity.lower()
        users = [e['username'] for e in details[ip]]
        top_user = Counter(users).most_common(1)[0][0] if users else 'N/A'
        rows += f'<tr class="{css}"><td>{ip}</td><td>{count}</td>' \
                f'<td><span class="badge {css}">{severity}</span></td><td>{top_user}</td></tr>'

    user_rows = "".join(f"<tr><td>{u}</td><td>{c}</td></tr>" for u, c in user_counter.most_common(15))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Windows Log Analysis Report</title>
<style>
:root {{ --bg:#0f172a; --card:#1e293b; --text:#e2e8f0; --muted:#94a3b8; --accent:#38bdf8;
         --critical:#ef4444; --suspicious:#f59e0b; --low:#22c55e; }}
* {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); padding:2rem; }}
.container {{ max-width:1100px; margin:0 auto; }}
h1 {{ font-size:1.8rem; color:var(--accent); margin-bottom:.3rem; }}
.subtitle {{ color:var(--muted); margin-bottom:2rem; }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:1rem; margin-bottom:2rem; }}
.stat-card {{ background:var(--card); border-radius:12px; padding:1.2rem; text-align:center; border:1px solid #334155; }}
.stat-card .value {{ font-size:2rem; font-weight:700; color:var(--accent); }}
.stat-card .label {{ color:var(--muted); font-size:.9rem; }}
table {{ width:100%; border-collapse:collapse; background:var(--card); border-radius:12px; overflow:hidden; margin-bottom:2rem; border:1px solid #334155; }}
th,td {{ padding:.85rem 1rem; text-align:left; }}
th {{ background:#0f172a; color:var(--muted); font-size:.85rem; text-transform:uppercase; }}
tr {{ border-bottom:1px solid #334155; }}
tr.critical {{ background:rgba(239,68,68,.12); }}
tr.suspicious {{ background:rgba(245,158,11,.10); }}
.badge {{ display:inline-block; padding:.25rem .6rem; border-radius:9999px; font-size:.75rem; font-weight:600; }}
.badge.critical {{ background:var(--critical); color:white; }}
.badge.suspicious {{ background:var(--suspicious); color:#1e293b; }}
.badge.low {{ background:var(--low); color:#1e293b; }}
h2 {{ margin:1.5rem 0 .8rem; color:var(--accent); }}
.footer {{ margin-top:2rem; color:var(--muted); font-size:.85rem; text-align:center; }}
</style>
</head>
<body>
<div class="container">
<h1>Windows Event Log Analysis</h1>
<p class="subtitle">Failed Logon Report (Event ID 4625) · Generated {now}</p>
<div class="stats">
<div class="stat-card"><div class="value">{total}</div><div class="label">Total Failed Logons</div></div>
<div class="stat-card"><div class="value">{len(ip_counter)}</div><div class="label">Unique Source IPs</div></div>
<div class="stat-card"><div class="value">{len(user_counter)}</div><div class="label">Unique Usernames</div></div>
<div class="stat-card"><div class="value">{sum(1 for c in ip_counter.values() if c >= threshold)}</div><div class="label">Suspicious / Critical IPs</div></div>
</div>
<h2>Source IP Summary</h2>
<table><thead><tr><th>IP Address</th><th>Failed Attempts</th><th>Severity</th><th>Most Targeted User</th></tr></thead>
<tbody>{rows}</tbody></table>
<h2>Most Targeted Usernames</h2>
<table><thead><tr><th>Username</th><th>Attempts</th></tr></thead>
<tbody>{user_rows}</tbody></table>
<p class="footer">Thresholds: ≥{threshold} = SUSPICIOUS · ≥{critical} = CRITICAL<br>Log File Analyser</p>
</div>
</body>
</html>"""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(color(f"✅ HTML → {output_path}", Colors.GREEN))


def interactive_mode() -> None:
    """Friendly, prompt-driven mode for users who don't want to pass CLI flags."""
    print()
    print(color("=" * 60, Colors.CYAN))
    print(color("  Windows Event Log Analyser - Interactive Mode", Colors.BOLD))
    print(color("=" * 60, Colors.CYAN))
    print()

    default_log = "sample_windows_security.log"
    log_input = input(f"Log file path [{default_log}]: ").strip()
    log_file = log_input if log_input else default_log

    if not Path(log_file).exists():
        print(color(f"\n❌ File not found: {log_file}", Colors.RED))
        return

    print()
    thresh_input = input(f"Suspicious threshold [{DEFAULT_THRESHOLD}]: ").strip()
    threshold = int(thresh_input) if thresh_input.isdigit() else DEFAULT_THRESHOLD

    crit_input = input(f"Critical threshold [{DEFAULT_CRITICAL}]: ").strip()
    critical = int(crit_input) if crit_input.isdigit() else DEFAULT_CRITICAL

    print()
    export_choice = input("Export CSV + JSON + HTML reports? (Y/n): ").strip().lower()
    do_export = export_choice != 'n'

    print()
    print(color(f"🔍 Analysing {log_file} ...", Colors.CYAN))

    ip_counter, user_counter, details = parse_log(log_file)

    if not ip_counter:
        print(color("⚠️  No Event ID 4625 (failed logon) entries found.", Colors.YELLOW))
        return

    print_terminal_report(ip_counter, user_counter, details, threshold, critical)

    if do_export:
        print()
        print(color("📁 Exporting reports...", Colors.CYAN))
        export_csv(ip_counter, details, "failed_logons_report.csv", threshold, critical)
        export_json(ip_counter, user_counter, details, "failed_logons_report.json", threshold, critical)
        export_html(ip_counter, user_counter, details, "failed_logons_report.html", threshold, critical)
        print()
        print(color("✅ All done!", Colors.GREEN + Colors.BOLD))
    else:
        print()
        print(color("✅ Analysis complete (no files exported).", Colors.GREEN))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Windows Event Log Analyser – Failed Logons & Suspicious IPs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyser.py                          # Interactive mode
  python log_analyser.py sample_windows_security.log
  python log_analyser.py Security.evtx             # Real Windows .evtx file
  python log_analyser.py mylog.txt -t 8 -c 20
  python log_analyser.py mylog.txt --no-export
        """
    )
    parser.add_argument('logfile', nargs='?', default=None,
                        help='Path to a log file: text export (.log/.txt) or real Windows (.evtx)')
    parser.add_argument('-t', '--threshold', type=int, default=DEFAULT_THRESHOLD,
                        help=f'Suspicious threshold (default: {DEFAULT_THRESHOLD})')
    parser.add_argument('-c', '--critical', type=int, default=DEFAULT_CRITICAL,
                        help=f'Critical threshold (default: {DEFAULT_CRITICAL})')
    parser.add_argument('--csv', default='failed_logons_report.csv',
                        help='CSV output filename')
    parser.add_argument('--json', default='failed_logons_report.json',
                        help='JSON output filename')
    parser.add_argument('--html', default='failed_logons_report.html',
                        help='HTML output filename')
    parser.add_argument('--no-export', action='store_true',
                        help='Skip CSV/JSON/HTML export')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Force interactive mode')

    args = parser.parse_args()

    # If no logfile given → go interactive
    if args.logfile is None or args.interactive:
        interactive_mode()
        return

    log_path = Path(args.logfile)
    if not log_path.exists():
        print(color(f"❌ Error: Log file not found → {log_path}", Colors.RED))
        print("   Tip: Run without arguments to use interactive mode.")
        return

    print(color(f"🔍 Analysing: {log_path}", Colors.CYAN))
    print(f"   Thresholds → Suspicious: ≥{args.threshold}  |  Critical: ≥{args.critical}")

    ip_counter, user_counter, details = parse_log(str(log_path))

    if not ip_counter:
        print(color("⚠️  No Event ID 4625 (failed logon) entries found.", Colors.YELLOW))
        return

    print_terminal_report(ip_counter, user_counter, details, args.threshold, args.critical)

    if not args.no_export:
        print()
        print(color("📁 Exporting reports...", Colors.CYAN))
        export_csv(ip_counter, details, args.csv, args.threshold, args.critical)
        export_json(ip_counter, user_counter, details, args.json, args.threshold, args.critical)
        export_html(ip_counter, user_counter, details, args.html, args.threshold, args.critical)
        print()
        print(color("✅ All done!", Colors.GREEN + Colors.BOLD))


if __name__ == "__main__":
    main()
