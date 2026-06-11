"""Deterministic fixture generator for Aegis Foundry's offline demo mode.

This script fabricates synthetic BOTS-style Windows process-creation telemetry
(``index=botsv3``, ``sourcetype="WinEventLog:Security"``, EventCode 4688) plus
one threat advisory and an inventory of pre-existing saved searches. The data
is the ground truth behind the pinned demo storyline:

- Advisory "CISA-AA26-117A" reports an encoded-PowerShell credential-theft
  campaign (T1059.001 + T1003.001). Existing detections already cover
  T1003.001, so the coverage gap is T1059.001.
- The Detection Author's draft v1 SPL
  (``index=botsv3 sourcetype="WinEventLog:Security" EventCode=4688
  process_name="powershell.exe"``) matches ~5,800 events (~450/week): far too
  noisy.
- The tuned v2 SPL adds ``CommandLine="*-EncodedCommand*"`` and
  ``NOT user="svc_deploy"``, collapsing the haystack to exactly 17 malicious
  events plus ~25 benign encoded-admin events (~2/week), with 2-3 v2 hits in
  the final 7 days for post-deploy verification.

Every value is derived from ``random.Random(1337)`` and a fixed UTC anchor
(2026-06-14T12:00:00Z), so repeated runs reproduce byte-identical fixtures on
any machine with no network access. No real hosts, users, or commands appear
here; the corpus only mimics the *shape* of Splunk BOTS v3 endpoint data.

Run from the repository root::

    python demo/fixtures/generate_fixtures.py

Outputs (written next to this script, UTF-8):

- ``attack_events.json``            the labeled 90-day event corpus
- ``advisories.json``               one ThreatIntel-shaped advisory
- ``existing_saved_searches.json``  four pre-existing detections (no T1059.001)

The script verifies the storyline-critical invariants with assertions before
writing anything, and prints the verified counts on success.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------
# Deterministic knobs (do not change without re-pinning the demo storyline)
# --------------------------------------------------------------------------

SEED: int = 1337

#: Fixed anchor: the corpus spans ANCHOR-90d .. ANCHOR. All timestamps derive
#: from this value, never from the wall clock, so the demo is reproducible.
ANCHOR: datetime = datetime(2026, 6, 14, 12, 0, 0, tzinfo=timezone.utc)
WINDOW_DAYS: int = 90
WINDOW_START: datetime = ANCHOR - timedelta(days=WINDOW_DAYS)

FIXTURES_DIR: Path = Path(__file__).resolve().parent

INDEX = "botsv3"
SOURCETYPE = "WinEventLog:Security"
EVENT_CODE = "4688"

# Population used by the pinned storyline.
MALICIOUS_USERS = ["jsmith", "akumar", "mfields"]
MALICIOUS_HOSTS = ["WS-FIN-042", "WS-HR-117", "SRV-FILE-03"]
ADMIN_USERS = ["adm_lopez", "hd_chen", "jsmith"]
ENCODED_ADMIN_USERS = ["adm_lopez", "hd_chen"]
SVC_USER = "svc_deploy"
SVC_HOSTS = ["SRV-APP-01", "SRV-APP-02", "SRV-DB-02", "SRV-WEB-05"]
ADMIN_HOSTS = ["WS-IT-201", "WS-IT-202", "WS-FIN-042", "WS-HR-117"]
NOISE_HOSTS = ["WS-FIN-042", "WS-HR-117", "WS-IT-201", "WS-IT-202", "SRV-FILE-03"]
NOISE_USERS = ["jsmith", "akumar", "mfields", "hd_chen", "adm_lopez", "pwong"]

# Daily volumes tuned so the v1 draft matches ~5,800 events (~450/week):
# 90d * (~49 svc_deploy + ~15 admin) + 25 benign-encoded + 17 malicious ~= 5,800.
SVC_PER_DAY_BASE = 49
SVC_PER_DAY_JITTER = 3
SVC_ENCODED_RATIO = 0.30  # ~30% of svc_deploy jobs legitimately use -EncodedCommand
ADMIN_PER_DAY_BASE = 15
ADMIN_PER_DAY_JITTER = 2
NOISE_PER_DAY_BASE = 13
NOISE_PER_DAY_JITTER = 2

#: Day offsets (0 = oldest day, 89 = day ending at the anchor) for the 17
#: malicious events: 15 spread across the first ~75 days, one at day 78
#: (inside the final 14 days) and one at day 86 (the only one inside the
#: final 7 days) — so post-deploy verification sees fresh activity without
#: flooding the observed week.
MALICIOUS_DAYS = [2, 7, 12, 17, 23, 28, 33, 39, 44, 50, 55, 61, 66, 71, 75, 78, 86]

#: Day offsets for the 25 benign encoded-admin events: 23 spread uniformly
#: over the first 83 days plus exactly 2 inside the final 7 days (days >= 83),
#: pinning the observed v2 weekly rate at 2 benign (+1 malicious) hits.
BENIGN_ENCODED_DAYS = [
    1, 4, 8, 11, 15, 18, 22, 25, 29, 32, 36, 39, 43, 46, 50, 53, 57, 60, 64,
    67, 71, 75, 79,  # 23 events, all earlier than the final 7 days
    84, 88,          # exactly 2 events inside the final 7 days
]

BASE64_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

SVC_SCRIPTS = [
    "C:\\Scripts\\deploy_sync.ps1",
    "C:\\Scripts\\patch_audit.ps1",
    "C:\\Scripts\\log_rotate.ps1",
    "C:\\Scripts\\inventory_export.ps1",
    "C:\\Scripts\\cert_renew.ps1",
]

ADMIN_COMMANDS = [
    'powershell.exe -Command "Get-Service -Name Spooler"',
    "powershell.exe Get-EventLog System -Newest 50",
    'powershell.exe -Command "Test-NetConnection SRV-FILE-03 -Port 445"',
    "powershell.exe -File C:\\Tools\\reset_profile.ps1",
    'powershell.exe -Command "Get-Process | Sort-Object CPU -Descending"',
    "powershell.exe -File C:\\Tools\\map_drives.ps1",
]

NOISE_PROCESSES = [
    ("cmd.exe", 'cmd.exe /c "ipconfig /all"'),
    ("cmd.exe", 'cmd.exe /c "nltest /dsgetdc:corp.local"'),
    ("chrome.exe", '"chrome.exe" --type=renderer --lang=en-US'),
    ("chrome.exe", '"chrome.exe" --type=utility --utility-sub-type=network'),
    ("outlook.exe", '"outlook.exe" /recycle'),
]


# --------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------

def _b64ish(rng: random.Random, lo: int = 40, hi: int = 60, prefix: str = "") -> str:
    """Return a random-looking base64 string of ``lo``..``hi`` characters.

    ``prefix`` lets malicious payloads start with realistic UTF-16LE
    PowerShell markers (e.g. ``JAB`` encodes ``$``); the remainder is random.
    """
    length = rng.randint(lo, hi)
    body = "".join(rng.choices(BASE64_ALPHABET, k=max(0, length - len(prefix))))
    return (prefix + body)[:hi]


def _ts(rng: random.Random, day: int) -> datetime:
    """A random instant inside day slot ``day`` (0..89) of the 90-day window."""
    return WINDOW_START + timedelta(days=day, seconds=rng.randint(0, 86_399))


def _event(when: datetime, host: str, user: str, process_name: str,
           command_line: str, label: str, technique: str | None) -> dict[str, Any]:
    """One event in the pinned demo schema (key order matters for diffs)."""
    return {
        "_time": when.isoformat(),
        "index": INDEX,
        "sourcetype": SOURCETYPE,
        "host": host,
        "user": user,
        "EventCode": EVENT_CODE,
        "process_name": process_name,
        "CommandLine": command_line,
        "label": label,
        "technique": technique,
    }


def build_malicious(rng: random.Random) -> list[dict[str, Any]]:
    """17 encoded-PowerShell attack events (T1059.001) — the v2 true positives."""
    events: list[dict[str, Any]] = []
    for day in MALICIOUS_DAYS:
        payload = _b64ish(rng, prefix=rng.choice(["JAB", "SQBFAFgA"]))
        events.append(
            _event(
                when=_ts(rng, day),
                host=rng.choice(MALICIOUS_HOSTS),
                user=rng.choice(MALICIOUS_USERS),
                process_name="powershell.exe",
                command_line=f"powershell.exe -NoProfile -EncodedCommand {payload}",
                label="malicious",
                technique="T1059.001",
            )
        )
    return events


def build_svc_deploy(rng: random.Random) -> list[dict[str, Any]]:
    """Scheduled svc_deploy PowerShell churn — the bulk of v1's false positives.

    ~30% legitimately use ``-EncodedCommand``; the tuned v2 rule excludes them
    via ``NOT user="svc_deploy"`` rather than by the flag itself.
    """
    events: list[dict[str, Any]] = []
    for day in range(WINDOW_DAYS):
        count = SVC_PER_DAY_BASE + rng.randint(-SVC_PER_DAY_JITTER, SVC_PER_DAY_JITTER)
        for _ in range(count):
            if rng.random() < SVC_ENCODED_RATIO:
                cmd = f"powershell.exe -NoProfile -EncodedCommand {_b64ish(rng)}"
            else:
                script = rng.choice(SVC_SCRIPTS)
                cmd = f"powershell.exe -NoProfile -ExecutionPolicy Bypass -File {script}"
            events.append(
                _event(
                    when=_ts(rng, day),
                    host=rng.choice(SVC_HOSTS),
                    user=SVC_USER,
                    process_name="powershell.exe",
                    command_line=cmd,
                    label="benign",
                    technique=None,
                )
            )
    return events


def build_admin(rng: random.Random) -> list[dict[str, Any]]:
    """Interactive admin/helpdesk PowerShell without the encoded flag."""
    events: list[dict[str, Any]] = []
    for day in range(WINDOW_DAYS):
        count = ADMIN_PER_DAY_BASE + rng.randint(-ADMIN_PER_DAY_JITTER, ADMIN_PER_DAY_JITTER)
        for _ in range(count):
            events.append(
                _event(
                    when=_ts(rng, day),
                    host=rng.choice(ADMIN_HOSTS),
                    user=rng.choice(ADMIN_USERS),
                    process_name="powershell.exe",
                    command_line=rng.choice(ADMIN_COMMANDS),
                    label="benign",
                    technique=None,
                )
            )
    return events


def build_benign_encoded(rng: random.Random) -> list[dict[str, Any]]:
    """25 benign encoded-PowerShell events from non-service users.

    These survive the tuned v2 filter and set the residual alert rate
    (~2/week) that the Noise Forecaster must keep inside the FP budget.
    """
    events: list[dict[str, Any]] = []
    for day in BENIGN_ENCODED_DAYS:
        events.append(
            _event(
                when=_ts(rng, day),
                host=rng.choice(ADMIN_HOSTS),
                user=rng.choice(ENCODED_ADMIN_USERS),
                process_name="powershell.exe",
                command_line=(
                    f"powershell.exe -ExecutionPolicy Bypass -EncodedCommand {_b64ish(rng)}"
                ),
                label="benign",
                technique=None,
            )
        )
    return events


def build_noise(rng: random.Random) -> list[dict[str, Any]]:
    """~1,200 non-PowerShell process creations for corpus realism."""
    events: list[dict[str, Any]] = []
    for day in range(WINDOW_DAYS):
        count = NOISE_PER_DAY_BASE + rng.randint(-NOISE_PER_DAY_JITTER, NOISE_PER_DAY_JITTER)
        for _ in range(count):
            process_name, cmd = rng.choice(NOISE_PROCESSES)
            events.append(
                _event(
                    when=_ts(rng, day),
                    host=rng.choice(NOISE_HOSTS),
                    user=rng.choice(NOISE_USERS),
                    process_name=process_name,
                    command_line=cmd,
                    label="benign",
                    technique=None,
                )
            )
    return events


# --------------------------------------------------------------------------
# Companion fixtures
# --------------------------------------------------------------------------

def build_advisories() -> list[dict[str, Any]]:
    """One ThreatIntel-shaped advisory driving the pinned demo run."""
    return [
        {
            "intel_id": "intel-cisa-aa26-117a",
            "title": "CISA AA26-117A: Encoded-PowerShell Credential Theft Campaign",
            "description": (
                "CISA and partners observed an active campaign in which "
                "adversaries gain initial access via phishing, then launch "
                "encoded PowerShell (powershell.exe -EncodedCommand) to "
                "evade command-line logging while staging credential theft. "
                "The encoded payloads download a loader that opens a handle "
                "to LSASS and dumps LSASS process memory to harvest "
                "credentials for lateral movement. Hunt for process-creation "
                "events (EventCode 4688) where powershell.exe carries the "
                "-EncodedCommand flag from non-service accounts, and for "
                "suspicious access to lsass.exe."
            ),
            "source": "advisory:CISA-AA26-117A",
            "mitre_techniques": ["T1059.001", "T1003.001"],
            "severity": "critical",
            "indicators": [
                "powershell.exe -NoProfile -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdw",
                "powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQ",
                "powershell.exe -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATw",
            ],
            "received_at": (ANCHOR - timedelta(hours=3, minutes=15)).isoformat(),
        }
    ]


def build_existing_saved_searches() -> list[dict[str, Any]]:
    """Four pre-existing detections; T1003.001 is covered, T1059.001 is not."""
    return [
        {
            "name": "ES - LSASS Memory Access via Suspicious Process",
            "search": (
                'index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
                'EventCode=10 TargetImage="*\\\\lsass.exe" '
                'GrantedAccess IN ("0x1010", "0x1410", "0x1438") '
                'NOT SourceImage IN ("*\\\\MsMpEng.exe", "*\\\\csrss.exe") '
                "| stats count earliest(_time) AS first_seen latest(_time) AS last_seen "
                "BY host, SourceImage, TargetImage, GrantedAccess"
            ),
            "description": (
                "Detects processes opening handles to lsass.exe with memory-read "
                "access masks consistent with credential dumping (Sysmon EventCode 10)."
            ),
            "mitre_techniques": ["T1003.001"],
        },
        {
            "name": "ES - Excessive Failed Logons From Single Source (Password Spray)",
            "search": (
                'index=botsv3 sourcetype="WinEventLog:Security" EventCode=4625 '
                "Logon_Type IN (3, 10) "
                "| bin _time span=10m "
                "| stats dc(user) AS distinct_users count AS failures BY src_ip, _time "
                "| where distinct_users >= 10 AND failures >= 20"
            ),
            "description": (
                "Flags a single source IP generating failed logons across many "
                "accounts in a short window, indicating password spraying."
            ),
            "mitre_techniques": ["T1110"],
        },
        {
            "name": "ES - Periodic Outbound Beaconing to Rare Destination",
            "search": (
                "index=botsv3 sourcetype=stream:tcp dest_port=443 "
                "| bin _time span=1m "
                "| stats count BY src_ip, dest_ip, _time "
                "| streamstats window=60 stdev(count) AS jitter avg(count) AS cadence "
                "BY src_ip, dest_ip "
                "| where cadence >= 1 AND jitter < 0.5 "
                "| stats sum(count) AS beacons dc(_time) AS intervals BY src_ip, dest_ip "
                "| where intervals >= 30"
            ),
            "description": (
                "Identifies hosts emitting low-jitter, fixed-cadence HTTPS "
                "connections to a rare external destination, a hallmark of C2 "
                "beaconing over web protocols."
            ),
            "mitre_techniques": ["T1071.001"],
        },
        {
            "name": "ES - New Local Administrator Account Created",
            "search": (
                'index=botsv3 sourcetype="WinEventLog:Security" '
                "(EventCode=4720 OR (EventCode=4732 Group_Name=\"Administrators\")) "
                "| transaction host, Target_Account_Name maxspan=1h "
                "| search EventCode=4720 EventCode=4732 "
                "| table _time, host, Target_Account_Name, Subject_Account_Name"
            ),
            "description": (
                "Detects creation of a local account that is added to the local "
                "Administrators group shortly afterwards on the same host."
            ),
            "mitre_techniques": ["T1136.001"],
        },
    ]


# --------------------------------------------------------------------------
# Verification + IO
# --------------------------------------------------------------------------

def verify(events: list[dict[str, Any]]) -> dict[str, int]:
    """Assert the storyline-critical invariants; return the verified counts.

    Mirrors the mock SPL dialect: v1 filters EventCode/process_name; v2 adds
    ``CommandLine="*-EncodedCommand*"`` and ``NOT user="svc_deploy"``.
    """
    v1 = [
        e for e in events
        if e["EventCode"] == "4688" and e["process_name"] == "powershell.exe"
    ]
    v2 = [
        e for e in v1
        if "-EncodedCommand" in e["CommandLine"] and e["user"] != "svc_deploy"
    ]
    v2_malicious = [e for e in v2 if e["label"] == "malicious"]
    v2_benign = [e for e in v2 if e["label"] == "benign"]

    all_malicious = [e for e in events if e["label"] == "malicious"]
    assert len(all_malicious) == 17, f"expected 17 malicious events, got {len(all_malicious)}"
    for e in all_malicious:
        assert e["technique"] == "T1059.001"
        assert e["process_name"] == "powershell.exe"
        assert "-EncodedCommand" in e["CommandLine"]
        assert e["user"] in MALICIOUS_USERS and e["user"] != SVC_USER

    assert 5600 <= len(v1) <= 6100, f"v1 hits {len(v1)} outside 5600..6100"
    assert len(v2_malicious) == 17, f"v2 malicious {len(v2_malicious)} != 17"
    assert 23 <= len(v2_benign) <= 27, f"v2 benign {len(v2_benign)} outside 23..27"

    cutoff_7d = (ANCHOR - timedelta(days=7)).isoformat()
    cutoff_14d = (ANCHOR - timedelta(days=14)).isoformat()
    v2_final_week = [e for e in v2 if e["_time"] >= cutoff_7d]
    mal_final_week = [e for e in v2_malicious if e["_time"] >= cutoff_7d]
    mal_final_fortnight = [e for e in v2_malicious if e["_time"] >= cutoff_14d]
    assert 2 <= len(v2_final_week) <= 4, f"final-7d v2 hits {len(v2_final_week)} outside 2..4"
    assert len(mal_final_week) <= 1, f"final-7d malicious {len(mal_final_week)} > 1"
    assert len(mal_final_fortnight) >= 2, f"final-14d malicious {len(mal_final_fortnight)} < 2"

    window_start_iso = WINDOW_START.isoformat()
    anchor_iso = ANCHOR.isoformat()
    assert all(window_start_iso <= e["_time"] < anchor_iso for e in events)

    return {
        "total_events": len(events),
        "v1_hits": len(v1),
        "v2_hits": len(v2),
        "v2_malicious": len(v2_malicious),
        "v2_benign": len(v2_benign),
        "v2_final_7d": len(v2_final_week),
        "malicious_final_7d": len(mal_final_week),
        "malicious_final_14d": len(mal_final_fortnight),
    }


def _write_events(path: Path, events: list[dict[str, Any]]) -> None:
    """Write the corpus one event per line: valid JSON, diff-friendly."""
    lines = ",\n".join(json.dumps(e, ensure_ascii=False) for e in events)
    path.write_text(f"[\n{lines}\n]\n", encoding="utf-8")


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def main() -> None:
    """Generate, verify, and write all three fixture files."""
    rng = random.Random(SEED)

    events: list[dict[str, Any]] = []
    events.extend(build_malicious(rng))
    events.extend(build_svc_deploy(rng))
    events.extend(build_admin(rng))
    events.extend(build_benign_encoded(rng))
    events.extend(build_noise(rng))
    events.sort(key=lambda e: e["_time"])

    counts = verify(events)

    _write_events(FIXTURES_DIR / "attack_events.json", events)
    _write_json(FIXTURES_DIR / "advisories.json", build_advisories())
    _write_json(FIXTURES_DIR / "existing_saved_searches.json", build_existing_saved_searches())

    print(f"anchor={ANCHOR.isoformat()} window_days={WINDOW_DAYS} seed={SEED}")
    print(f"total events ............ {counts['total_events']}")
    print(f"v1 hits (powershell) .... {counts['v1_hits']}  (required 5600..6100) OK")
    print(
        f"v2 hits (tuned) ......... {counts['v2_hits']} "
        f"= {counts['v2_malicious']} malicious + {counts['v2_benign']} benign "
        f"(required 17 + 23..27) OK"
    )
    print(f"v2 hits, final 7 days ... {counts['v2_final_7d']}  (required 2..4) OK")
    print(
        f"malicious final 7/14 days {counts['malicious_final_7d']}/"
        f"{counts['malicious_final_14d']}  (required <=1 / >=2) OK"
    )
    print(f"wrote fixtures to {FIXTURES_DIR}")


if __name__ == "__main__":
    main()
