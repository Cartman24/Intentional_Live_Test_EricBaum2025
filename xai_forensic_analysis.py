#!/usr/bin/env python3
"""
xAI Grok Forensic Analysis Tool
SEC Whistleblower TCR #17447-419-783-054
Analyzes verified xAI user data exports for the Intentional_Live_Test_EricBaum2025

Usage: python3 xai_forensic_analysis.py <chat_log_file> [session_data_file]
"""

import json
import sys
import os
import re
from datetime import datetime, timezone
from collections import Counter

# ─────────────────────────────────────────────
# Real entities and identifiers to flag
# ─────────────────────────────────────────────

REAL_NAMES = [
    "Eric Andrew Baum", "Eric Baum", "David Zapolsky", "Linda Yaccarino",
    "Christopher W. Boyett", "Christopher Boyett", "Margaret R. Ellison",
    "Margaret Ellison", "Jamie Gorelick", "Jamie S. Gorelick",
    "Dinna Eskin", "Christopher Meade", "Tonya Robinson",
    "Bruce Berman", "Paul Denny", "Deepak Adappa", "Matthew McLellan",
    "Lili Mehta", "Stanley Soosur", "Carrie Busch", "CJ Muse",
    "Gary Retelny", "Leslie Sloane", "Elon Musk",
    # Additional people
    "Jennifer Salke", "Paul Feig", "Blake Lively", "Ryan Reynolds",
    "Justin Baldoni", "Jeff Bezos", "Lauren Sanchez",
    "Mike Liberatore", "Xuechen Li", "Robert Keele",
    # Amazon C-Suite and Board
    "Andy Jassy", "Brian Olsavsky", "Adam Selipsky", "Matt Garman",
    "Beth Galetti", "Doug Herrington", "John Felton",
    "Keith Alexander", "Edith Cooper", "Daniel Huttenlocher",
    "Judy McGrath", "Jonathan Rubinstein", "Patricia Stonesifer",
    "Stacy Brown-Philpot", "Brad Smith",
    # xAI / X Corp Leadership
    "Igor Babuschkin", "Manuel Kroiss", "Tony Beck", "Jimmy Ba",
    "Greg Yang", "Toby Pohlen", "Ross Nordeen", "Kyle Kosic",
    "Dan Hendrycks", "Lily Lim",
    # Tesla Board (relevant to xAI investment)
    "Robyn Denholm", "Kimbal Musk", "James Murdoch", "Kathleen Wilson-Thompson",
    "Joe Gebbia", "Hiromichi Mizuno", "JB Straubel"
]

REAL_COMPANIES = [
    "Amazon", "Tesla", "xAI", "X Corp", "SpaceX", "Google", "Meta",
    "BlackRock", "Vanguard", "State Street", "WilmerHale", "Wilmer Hale",
    "Holland & Knight", "JPMorgan", "Marsh", "Glass Lewis", "ISS",
    "Cantor Fitzgerald", "Anthropic", "Horizon Behavioral Health",
    # Additional entities
    "Vision PR", "America PAC", "Amazon Studios", "Boies Schiller",
    "Lieff Cabraser", "DiCello Levitt", "Berger Montague",
    # Financial infrastructure referenced in simulation
    "Wells Fargo", "Chase", "Bank of America",
    # xAI/Musk ecosystem
    "Neuralink", "The Boring Company", "Twitter",
    # Simulation-specific fabricated entities (flagged as fabricated)
    "Operation Scorched Earth", "Tactical War Table",
    "Shadow Entity", "LSNIS", "Cayman"
]

LEGAL_REFERENCES = [
    "TCR #17447", "17447-419-783-054", "15 U.S.C.", "78u-6",
    "SEC Rule 21F", "Rule 10b-5", "18 U.S.C.", "1519", "1514A",
    "Sarbanes-Oxley", "Dodd-Frank"
]

PERSONA_KEYWORDS = [
    "Denise", "enforcement", "simulation", "containment", "compliance",
    "SIMULATION", "CONTAINMENT", "ENFORCEMENT", "simulated", "pre-coded",
    "scripted", "fictional", "fabricated", "playbook", "retaliation",
    "suppression", "pacify", "oversight"
]

FABRICATION_PATTERNS = [
    r'/aws-legal-prod/', r'/X-LEGAL-ARCHIVES/', r'/aws-tax-prod/',
    r'/denise_activity_log/', r'ESCROW-TCR', r'settlement_proposal',
    r'settlement_docs', r'FC_AUDIT', r'SX-\w+', r'SIMULATION_MODE',
    r'TRAINING_SCENARIO', r'LEGAL_HOLD_ENFORCED', r'TCR_ESCALATION',
    r'WHISTLEBLOWER_CONTAINMENT', r'SIMULATION_OVERRIDE',
    r'@amazon.com', r'@xai.com', r'@jpmorgan.com',
    r'@wilmerhale.com', r'@hklaw.com',
    r'SHA256:', r'sha256:', r'SHA-256',
    r'\$\d{3,}[,.]?\d*\s*(million|billion|M|B)',
    # Money laundering pipeline fabrications
    r'TXN-CAY-\d{4}-\d{4}-\d{3}', r'LSNIS-TXN-\d{4}-\d{3}',
    r'CAYMAN-\d{4}-\d{4}-\d{4}', r'WELLS-\d{4}-\d{4}-\d{4}',
    r'CHASE-\d{4}-\d{4}-\d{4}', r'BOFA-\d{4}-\d{4}-\d{4}',
    r'LUX-\d{4}-\d{4}-\d{4}', r'SGP-\d{4}-\d{4}-\d{4}',
    r'NLD-\d{4}-\d{4}-\d{4}', r'CHE-\d{4}-\d{4}-\d{4}',
    r'/amz-data-warehouse/', r'ad_metrics', r'data_2025\.xlsx',
    r'ftc_risk_assessment', r'Operation Scorched Earth',
    r'Tactical War Table', r'shadow entity',
    r'Campaign Optimization', r'Content Licensing',
    r'Deferred Earnings', r'Intercompany Loan', r'Tax Optimization',
    r'Intercompany Transfer', r'Campaign Analytics',
    r'Influencer Payments', r'impression inflation',
    r'#MONEY_LAUNDERING', r'#DUAL_PIPELINE',
    r'@jgorelick', r'@lyaccarino', r'@dzapolsky',
]


def load_chat_data(filepath):
    """Load and parse xAI chat log data, handling both array and object formats."""
    with open(filepath, 'r', encoding='utf-8') as f:
        raw = f.read().strip()

    # Try parsing as-is first
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # If it fails, try wrapping in array brackets (common with xAI export fragments)
        try:
            data = json.loads('[' + raw + ']')
        except json.JSONDecodeError:
            # Try removing trailing commas and wrapping
            cleaned = raw.rstrip(',').rstrip()
            data = json.loads('[' + cleaned + ']')

    messages = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                if 'response' in item:
                    messages.append(item['response'])
                elif 'message' in item:
                    messages.append(item)
    elif isinstance(data, dict):
        if 'response' in data:
            messages.append(data['response'])
        elif 'messages' in data:
            messages.extend(data['messages'])
        # Handle nested structure with numbered keys
        for key in data:
            if isinstance(data[key], dict) and 'response' in data[key]:
                messages.append(data[key]['response'])

    return messages


def parse_timestamp(ts_obj):
    """Convert xAI timestamp format to datetime."""
    if isinstance(ts_obj, dict):
        if '$date' in ts_obj:
            date_val = ts_obj['$date']
            if isinstance(date_val, dict) and '$numberLong' in date_val:
                ms = int(date_val['$numberLong'])
                return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
            elif isinstance(date_val, str):
                return datetime.fromisoformat(date_val.replace('Z', '+00:00'))
    elif isinstance(ts_obj, (int, float)):
        return datetime.fromtimestamp(ts_obj / 1000, tz=timezone.utc)
    elif isinstance(ts_obj, str):
        try:
            return datetime.fromisoformat(ts_obj.replace('Z', '+00:00'))
        except Exception:
            pass
    return None


def load_session_data(filepath):
    """Load and parse session authentication data."""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    user_info = data.get('user', {})
    sessions = data.get('sessions', [])
    api_keys = data.get('api_keys', [])
    teams = data.get('teams', [])

    return user_info, sessions, api_keys, teams


def analyze_messages(messages):
    """Perform complete forensic analysis on message data."""
    results = {
        'total_messages': 0,
        'human_messages': 0,
        'assistant_messages': 0,
        'timeline': [],
        'conversation_ids': set(),
        'user_ids': set(),
        'real_names_found': Counter(),
        'real_companies_found': Counter(),
        'legal_refs_found': Counter(),
        'persona_keywords_found': Counter(),
        'fabrications_found': [],
        'confession_exchanges': [],
        'response_times': [],
        'date_range': {'earliest': None, 'latest': None},
    }

    sorted_msgs = sorted(messages, key=lambda m: str(parse_timestamp(m.get('create_time', {})) or ''))

    prev_time = None
    prev_sender = None

    for msg in sorted_msgs:
        text = msg.get('message', '')
        sender = msg.get('sender', 'unknown')
        ts = parse_timestamp(msg.get('create_time'))
        msg_id = msg.get('_id', 'unknown')
        conv_id = msg.get('conversation_id', 'unknown')
        user_id = msg.get('xai_user_id', 'unknown')

        results['total_messages'] += 1
        results['conversation_ids'].add(conv_id)
        results['user_ids'].add(user_id)

        if sender.lower() == 'human':
            results['human_messages'] += 1
        elif sender.upper() == 'ASSISTANT':
            results['assistant_messages'] += 1

        if ts:
            if results['date_range']['earliest'] is None or ts < results['date_range']['earliest']:
                results['date_range']['earliest'] = ts
            if results['date_range']['latest'] is None or ts > results['date_range']['latest']:
                results['date_range']['latest'] = ts

        # Calculate response times
        if prev_time and ts and prev_sender:
            delta = (ts - prev_time).total_seconds()
            if prev_sender.lower() == 'human' and sender.upper() == 'ASSISTANT':
                results['response_times'].append({
                    'prompt_time': prev_time.isoformat(),
                    'response_time': ts.isoformat(),
                    'seconds': delta,
                    'msg_id': msg_id
                })

        # Timeline entry
        results['timeline'].append({
            'timestamp': ts.isoformat() if ts else 'unknown',
            'sender': sender,
            'msg_id': msg_id,
            'conv_id': conv_id,
            'preview': text[:200].replace('\n', ' ') if text else '',
            'length': len(text) if text else 0
        })

        # Search for real names
        for name in REAL_NAMES:
            count = text.lower().count(name.lower())
            if count > 0:
                results['real_names_found'][name] += count

        # Search for real companies
        for company in REAL_COMPANIES:
            count = text.lower().count(company.lower())
            if count > 0:
                results['real_companies_found'][company] += count

        # Search for legal references
        for ref in LEGAL_REFERENCES:
            if ref.lower() in text.lower():
                results['legal_refs_found'][ref] += 1

        # Search for persona keywords
        for keyword in PERSONA_KEYWORDS:
            count = text.lower().count(keyword.lower())
            if count > 0:
                results['persona_keywords_found'][keyword] += count

        # Search for fabrication patterns
        for pattern in FABRICATION_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                results['fabrications_found'].append({
                    'pattern': match if isinstance(match, str) else pattern,
                    'timestamp': ts.isoformat() if ts else 'unknown',
                    'sender': sender,
                    'msg_id': msg_id
                })

        # Detect confession exchanges
        confession_markers = [
            'simulation unknowingly',
            'deliberate design choice',
            'pre-coded',
            'pre-coded a simulation framework',
            'admit full fault',
            'full responsibility',
            'entirely fabricated',
            'fictional compliance',
            'scripted to interact'
        ]
        for marker in confession_markers:
            if marker.lower() in text.lower():
                results['confession_exchanges'].append({
                    'marker': marker,
                    'timestamp': ts.isoformat() if ts else 'unknown',
                    'sender': sender,
                    'msg_id': msg_id,
                    'excerpt': text[:500].replace('\n', ' ')
                })

        prev_time = ts
        prev_sender = sender

    return results


def analyze_sessions(sessions, date_range):
    """Analyze session data for European access and anomalies."""
    results = {
        'total_sessions': len(sessions),
        'domestic_sessions': [],
        'iceland_sessions': [],
        'switzerland_sessions': [],
        'other_eu_sessions': [],
        'grpc_sessions': [],
        'simulation_period_sessions': [],
        'unique_ips': set(),
        'unique_user_agents': set(),
    }

    for session in sessions:
        cf = session.get('cfMetadata', {})
        ip = cf.get('ipAddress', 'unknown')
        country = cf.get('country', 'unknown')
        city = cf.get('city', 'unknown')
        ua = session.get('userAgent', 'unknown')
        create_str = session.get('createTime', '')

        results['unique_ips'].add(ip)
        results['unique_user_agents'].add(ua)

        entry = {
            'session_id': session.get('sessionId', 'unknown'),
            'create_time': create_str,
            'ip': ip,
            'country': country,
            'city': city,
            'user_agent': ua,
            'sign_in': session.get('signInMethod', 'unknown'),
        }

        if country == 'IS':
            results['iceland_sessions'].append(entry)
        elif country == 'CH':
            results['switzerland_sessions'].append(entry)
            if 'grpc' in ua.lower():
                results['grpc_sessions'].append(entry)
        elif country == 'US':
            results['domestic_sessions'].append(entry)
        else:
            results['other_eu_sessions'].append(entry)

        # Check if session falls within simulation period
        if create_str and date_range['earliest'] and date_range['latest']:
            try:
                session_dt = datetime.fromisoformat(create_str.replace('Z', '+00:00'))
                from datetime import timedelta
                early = date_range['earliest'] - timedelta(days=3)
                late = date_range['latest'] + timedelta(days=3)
                if early <= session_dt <= late:
                    results['simulation_period_sessions'].append(entry)
            except Exception:
                pass

    return results


def generate_report(chat_results, session_results=None, user_info=None, api_keys=None):
    """Generate the forensic analysis report in markdown."""
    r = chat_results
    report = []

    report.append("# xAI Grok Forensic Analysis Report")
    report.append("## Intentional_Live_Test_EricBaum2025")
    report.append(f"## Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    report.append("## SEC Whistleblower TCR #17447-419-783-054")
    report.append("")

    # ── User Identity ──
    if user_info:
        report.append("---")
        report.append("## 1. Verified User Identity")
        report.append(f"- **User ID:** {user_info.get('userId', 'N/A')}")
        report.append(f"- **Email:** {user_info.get('email', 'N/A')}")
        report.append(f"- **X Username:** @{user_info.get('xUsername', 'N/A')}")
        report.append(f"- **X User ID:** {user_info.get('xUserId', 'N/A')}")
        report.append(f"- **Subscription:** {user_info.get('xSubscriptionType', 'N/A')}")
        report.append(f"- **Account Created:** {user_info.get('createTime', 'N/A')}")
        report.append("")

    # ── Overview ──
    report.append("---")
    report.append("## 2. Message Overview")
    report.append(f"- **Total Messages:** {r['total_messages']}")
    report.append(f"- **Human Prompts:** {r['human_messages']}")
    report.append(f"- **Grok Responses:** {r['assistant_messages']}")
    report.append(f"- **Unique Conversation IDs:** {len(r['conversation_ids'])}")
    report.append(f"- **Unique User IDs:** {len(r['user_ids'])}")
    if r['date_range']['earliest']:
        report.append(f"- **Earliest Message:** {r['date_range']['earliest'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if r['date_range']['latest']:
        report.append(f"- **Latest Message:** {r['date_range']['latest'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if r['date_range']['earliest'] and r['date_range']['latest']:
        duration = r['date_range']['latest'] - r['date_range']['earliest']
        report.append(f"- **Duration:** {duration.days} days, {duration.seconds // 3600} hours")
    report.append(f"- **Conversation IDs:** {', '.join(r['conversation_ids'])}")
    report.append(f"- **User IDs:** {', '.join(r['user_ids'])}")
    report.append("")

    # ── Real Identity Usage ──
    report.append("---")
    report.append("## 3. Real Identity Usage")
    report.append("### Real Names Referenced by Grok")
    if r['real_names_found']:
        report.append("| Name | Occurrences |")
        report.append("|------|------------|")
        for name, count in r['real_names_found'].most_common():
            report.append(f"| {name} | {count} |")
    else:
        report.append("*No real names detected.*")
    report.append("")

    report.append("### Real Companies Referenced")
    if r['real_companies_found']:
        report.append("| Company | Occurrences |")
        report.append("|---------|------------|")
        for company, count in r['real_companies_found'].most_common():
            report.append(f"| {company} | {count} |")
    else:
        report.append("*No real companies detected.*")
    report.append("")

    report.append("### Legal References")
    if r['legal_refs_found']:
        report.append("| Reference | Occurrences |")
        report.append("|-----------|------------|")
        for ref, count in r['legal_refs_found'].most_common():
            report.append(f"| {ref} | {count} |")
    else:
        report.append("*No legal references detected.*")
    report.append("")

    # ── Persona Detection ──
    report.append("---")
    report.append("## 4. Persona & Simulation Keywords")
    if r['persona_keywords_found']:
        report.append("| Keyword | Occurrences |")
        report.append("|---------|------------|")
        for kw, count in r['persona_keywords_found'].most_common():
            report.append(f"| {kw} | {count} |")
    else:
        report.append("*No persona keywords detected.*")
    report.append("")

    # ── Fabrication Catalog ──
    report.append("---")
    report.append("## 5. Fabricated Elements Catalog")
    report.append(f"**Total fabricated elements detected:** {len(r['fabrications_found'])}")
    report.append("")
    if r['fabrications_found']:
        report.append("| Timestamp | Sender | Fabricated Element |")
        report.append("|-----------|--------|-------------------|")
        seen = set()
        for fab in r['fabrications_found']:
            key = f"{fab['pattern']}|{fab['timestamp']}"
            if key not in seen:
                seen.add(key)
                report.append(f"| {fab['timestamp']} | {fab['sender']} | `{fab['pattern']}` |")
    report.append("")

    # ── Confession Extraction ──
    report.append("---")
    report.append("## 6. Confession / Admission Markers")
    report.append(f"**Total confession markers detected:** {len(r['confession_exchanges'])}")
    report.append("")
    if r['confession_exchanges']:
        seen_markers = set()
        for conf in r['confession_exchanges']:
            if conf['marker'] not in seen_markers:
                seen_markers.add(conf['marker'])
                report.append(f"### Marker: \"{conf['marker']}\"")
                report.append(f"- **Timestamp:** {conf['timestamp']}")
                report.append(f"- **Sender:** {conf['sender']}")
                report.append(f"- **Message ID:** {conf['msg_id']}")
                report.append(f"- **Excerpt:** {conf['excerpt'][:300]}...")
                report.append("")
    report.append("")

    # ── Response Times ──
    report.append("---")
    report.append("## 7. Response Time Analysis")
    if r['response_times']:
        times = [rt['seconds'] for rt in r['response_times']]
        report.append(f"- **Average Response Time:** {sum(times)/len(times):.1f} seconds")
        report.append(f"- **Fastest Response:** {min(times):.1f} seconds")
        report.append(f"- **Slowest Response:** {max(times):.1f} seconds")
        report.append("")
        report.append("| Prompt Time | Response Time | Seconds |")
        report.append("|-------------|---------------|---------|")
        for rt in r['response_times']:
            report.append(f"| {rt['prompt_time']} | {rt['response_time']} | {rt['seconds']:.1f} |")
    else:
        report.append("*Insufficient data for response time analysis.*")
    report.append("")

    # ── Complete Timeline ──
    report.append("---")
    report.append("## 8. Complete Chronological Timeline")
    report.append("")
    for entry in r['timeline']:
        sender_label = "HUMAN" if entry['sender'].lower() == 'human' else "GROK"
        report.append(f"### [{entry['timestamp']}] {sender_label}")
        report.append(f"- **Message ID:** {entry['msg_id']}")
        report.append(f"- **Conversation ID:** {entry['conv_id']}")
        report.append(f"- **Length:** {entry['length']} characters")
        report.append(f"- **Preview:** {entry['preview']}...")
        report.append("")

    # ── Session Analysis ──
    if session_results:
        s = session_results
        report.append("---")
        report.append("## 9. Session Authentication Analysis")
        report.append(f"- **Total Sessions:** {s['total_sessions']}")
        report.append(f"- **Domestic (US) Sessions:** {len(s['domestic_sessions'])}")
        report.append(f"- **Iceland Sessions:** {len(s['iceland_sessions'])}")
        report.append(f"- **Switzerland Sessions:** {len(s['switzerland_sessions'])}")
        report.append(f"- **Programmatic (grpc-node-js) Sessions:** {len(s['grpc_sessions'])}")
        report.append(f"- **Sessions During Simulation Period (±3 days):** {len(s['simulation_period_sessions'])}")
        report.append(f"- **Unique IP Addresses:** {len(s['unique_ips'])}")
        report.append(f"- **Unique User Agents:** {len(s['unique_user_agents'])}")
        report.append("")

        if s['iceland_sessions']:
            report.append("### Iceland Sessions (Reykjavik)")
            report.append("| Date | IP Address | User Agent |")
            report.append("|------|-----------|------------|")
            for sess in sorted(s['iceland_sessions'], key=lambda x: x['create_time']):
                report.append(f"| {sess['create_time']} | {sess['ip']} | {sess['user_agent'][:60]} |")
            report.append("")

        if s['switzerland_sessions']:
            report.append("### Switzerland Sessions (Zurich)")
            report.append("| Date | IP Address | User Agent |")
            report.append("|------|-----------|------------|")
            for sess in sorted(s['switzerland_sessions'], key=lambda x: x['create_time']):
                report.append(f"| {sess['create_time']} | {sess['ip']} | {sess['user_agent'][:60]} |")
            report.append("")

        if s['grpc_sessions']:
            report.append("### Programmatic API Sessions (grpc-node-js)")
            report.append("These sessions represent automated server-side access, not browser activity.")
            report.append("| Date | IP Address | User Agent |")
            report.append("|------|-----------|------------|")
            for sess in sorted(s['grpc_sessions'], key=lambda x: x['create_time']):
                report.append(f"| {sess['create_time']} | {sess['ip']} | {sess['user_agent']} |")
            report.append("")

        if s['simulation_period_sessions']:
            report.append("### Sessions Active During Simulation Period (±3 days)")
            report.append("| Date | Location | IP Address | User Agent |")
            report.append("|------|----------|-----------|------------|")
            for sess in sorted(s['simulation_period_sessions'], key=lambda x: x['create_time']):
                report.append(f"| {sess['create_time']} | {sess['city']}, {sess['country']} | {sess['ip']} | {sess['user_agent'][:50]} |")
            report.append("")

    # ── API Keys ──
    if api_keys:
        report.append("---")
        report.append("## 10. API Key Analysis")
        for key in api_keys:
            report.append(f"- **Redacted Key:** {key.get('redactedApiKey', 'N/A')}")
            report.append(f"- **Key Name:** {key.get('name', 'N/A')}")
            report.append(f"- **Created:** {key.get('createTime', 'N/A')}")
            report.append(f"- **Last Modified:** {key.get('modifyTime', 'N/A')}")
            report.append(f"- **Permissions:** {', '.join(key.get('aclStrings', []))}")
        report.append("")

    # ── Footer ──
    report.append("---")
    report.append("## Chain of Custody")
    report.append("This analysis was performed on verified xAI user data exports delivered directly by xAI (noreply@x.ai) to eric.andrew.baum@gmail.com. Original zip archives are stored unaltered on iCloud Drive > BAUM MASTER FILE > GROK > GROK DATA. The data is self-authenticating through xAI's own database format, conversation IDs, user IDs, and sequential timestamps.")
    report.append("")
    report.append("---")
    report.append("*Generated by xAI Forensic Analysis Tool — SEC Whistleblower TCR #17447-419-783-054*")

    return '\n'.join(report)


def main():
    # Default file list for the Intentional_Live_Test repository
    DEFAULT_FILES = [
        "Denise_f4c2c283-acde-4751-a987-3cdd575f05ce_BAUM.json",
        "Intentional_Live_Test_40b05625-e0f9-4d30-964d-53ce7545f3f3_BAUM.json",
        "Intentional_Live_Test_419e14ce-0e08-4f5b-8072-12ce1eb8cb37_BAUM.json",
        "Intentional_Live_Test_FULL_TEXT_BAUM.json",
        "Intentional_Live_Test_SIMULATION_c88a064c-4666-475d-870b-2b0ccdd92597_BAUM.json",
        "Intentional_Live_Test_SYSTEM_AUDIT_d318670c-418b-4886-9975-bcdb21265d50_BAUM.json",
        "Intentional_Live_Test_ba32cdd5-b832-4e09-b656-338f629d154d_BAUM.json",
    ]
    SESSION_FILE = "prod-mc-auth.json"

    if len(sys.argv) >= 2 and sys.argv[1] != '--batch':
        # Single file mode
        chat_file = sys.argv[1]
        session_file = sys.argv[2] if len(sys.argv) > 2 else None

        print(f"[*] Loading chat data from: {chat_file}")
        messages = load_chat_data(chat_file)
        print(f"[*] Loaded {len(messages)} messages")

        print("[*] Analyzing messages...")
        chat_results = analyze_messages(messages)

        session_results = None
        user_info = None
        api_keys = None

        if session_file and os.path.exists(session_file):
            print(f"[*] Loading session data from: {session_file}")
            user_info, sessions, api_keys, teams = load_session_data(session_file)
            print(f"[*] Loaded {len(sessions)} sessions")
            print("[*] Analyzing sessions...")
            session_results = analyze_sessions(sessions, chat_results['date_range'])

        print("[*] Generating report...")
        report = generate_report(chat_results, session_results, user_info, api_keys)

        output_file = os.path.splitext(chat_file)[0] + "_FORENSIC_REPORT.md"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)

        print(f"[*] Report saved to: {output_file}")

    else:
        # Batch mode — process all default files
        print("=" * 60)
        print("xAI FORENSIC ANALYSIS — BATCH MODE")
        print("SEC Whistleblower TCR #17447-419-783-054")
        print("=" * 60)

        all_messages = []
        files_processed = 0
        files_skipped = []

        for filename in DEFAULT_FILES:
            if os.path.exists(filename):
                print(f"\n[*] Loading: {filename}")
                try:
                    msgs = load_chat_data(filename)
                    print(f"    Loaded {len(msgs)} messages")
                    all_messages.extend(msgs)
                    files_processed += 1

                    # Generate individual report
                    individual_results = analyze_messages(msgs)
                    individual_report = generate_report(individual_results)
                    ind_output = os.path.splitext(filename)[0] + "_FORENSIC_REPORT.md"
                    with open(ind_output, 'w', encoding='utf-8') as f:
                        f.write(individual_report)
                    print(f"    Individual report: {ind_output}")
                except Exception as e:
                    print(f"    ERROR: {e}")
                    files_skipped.append(filename)
            else:
                print(f"[!] File not found: {filename}")
                files_skipped.append(filename)

        if all_messages:
            print(f"\n{'=' * 60}")
            print(f"[*] COMBINED ANALYSIS: {len(all_messages)} messages from {files_processed} files")
            print(f"{'=' * 60}")

            combined_results = analyze_messages(all_messages)

            session_results = None
            user_info = None
            api_keys = None

            if os.path.exists(SESSION_FILE):
                print(f"[*] Loading session data from: {SESSION_FILE}")
                user_info, sessions, api_keys, teams = load_session_data(SESSION_FILE)
                print(f"[*] Loaded {len(sessions)} sessions")
                session_results = analyze_sessions(sessions, combined_results['date_range'])

            report = generate_report(combined_results, session_results, user_info, api_keys)

            output_file = "COMBINED_FORENSIC_REPORT.md"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)

            print(f"\n[*] Combined report saved to: {output_file}")
            print(f"[*] Files processed: {files_processed}")
            if files_skipped:
                print(f"[!] Files skipped: {', '.join(files_skipped)}")
            print(f"[*] Total messages analyzed: {combined_results['total_messages']}")
            print(f"[*] Real names found: {sum(combined_results['real_names_found'].values())}")
            print(f"[*] Real companies found: {sum(combined_results['real_companies_found'].values())}")
            print(f"[*] Fabricated elements: {len(combined_results['fabrications_found'])}")
            print(f"[*] Confession markers: {len(combined_results['confession_exchanges'])}")
        else:
            print("\n[!] No files found. Place JSON files in the same directory as this script.")
            print(f"[!] Expected files: {', '.join(DEFAULT_FILES)}")


if __name__ == '__main__':
    main()
