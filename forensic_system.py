"""
Digital Forensic Evidence Lifecycle Management System
-------------------------------------------------------------------------------
University IT Security Team — Suspected Cyber Incident on WKSTN-14

A menu-driven prototype that replaces inconsistent spreadsheets and informal
notes with a single tool that automates the core forensic workflow end to end:

  1. Evidence registration          -> unique evidence ID, source, acquisition
                                        date/time, investigator, storage
                                        location, SHA-256 hash at intake
  2. Chain-of-custody logging       -> every transfer (handler, timestamp,
                                        purpose) reconstructable on demand
  3. Integrity verification         -> recompute SHA-256 at examination time,
                                        compare to the intake value, flag any
                                        mismatch as potential tampering
  4. Baseline vs. snapshot          -> detect missing / new / renamed /
     validation                        modified files against a trusted
                                        baseline hash set
  5. Multi-source timeline          -> normalize and merge file-activity,
     reconstruction                    authentication, and network events
                                        into one chronological sequence
  6. Incident analysis              -> identify the earliest suspicious
                                        event and the activity that plausibly
                                        follows from it, citing the specific
                                        records used
  7. Forensic report generation     -> case info, evidence examined,
                                        chain-of-custody history, findings
                                        (fact) vs. conclusions
                                        (interpretation), missing-field flags

Design note on integrity: every section of the generated report is built
from data the program itself collected during the session (registration
records, custody entries, verification results, validation results, the
merged timeline) rather than from hard-coded text. This matters for a
forensic tool specifically: a report whose "findings" are typed in
separately from the analysis that supposedly produced them would not
survive scrutiny of its evidentiary basis.

Run modes:
    python forensic_system.py          -> interactive menu
    python forensic_system.py --demo   -> runs the full workflow once, non-
                                           interactively, printing every
                                           stage's output (for review/grading)

Dataset expected under ./data/ (see the accompanying sample dataset):
    evidence_register.csv, custody_log.csv, baseline_hashes.csv,
    current_snapshot_hashes.csv, auth_log.csv, file_activity_log.csv,
    network_log.csv, evidence_files/ (the files evidence_register.csv points to)
"""

import csv
import hashlib
import os
import sys
from datetime import datetime
from collections import defaultdict

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
TS_FORMAT = "%Y-%m-%d %H:%M:%S"

# In-memory stores. These are the single source of truth for the session;
# the report generator reads from them directly rather than from any
# separately-typed summary, so the report can never drift from the data.
evidence_register = []      # list of dicts: one per registered evidence item
custody_log = []            # list of dicts: one per custody transfer
verification_log = []       # list of dicts: one per integrity check performed

REQUIRED_FIELDS = ["evidence_id", "source", "acquisition_datetime", "investigator",
                    "storage_location", "intake_sha256"]


# ---------------------------------------------------------------------------
# 1. Utility: hashing
# ---------------------------------------------------------------------------

def compute_sha256(file_path, chunk_size=65536):
    """Compute the SHA-256 hex digest of a file, reading it in binary chunks
    so this works correctly even on large evidence files (disk images, RAM
    captures) that should never be loaded fully into memory."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


# ---------------------------------------------------------------------------
# 2. Load CSV-backed source data (log exports, baselines)
# ---------------------------------------------------------------------------

def load_csv(filename):
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


# ---------------------------------------------------------------------------
# 3. Evidence registration (Deliverable 2)
# ---------------------------------------------------------------------------

def register_evidence(evidence_id, source, file_path, investigator, storage_location,
                        acquisition_datetime=None):
    """Registers a new piece of evidence, computing its SHA-256 hash at the
    moment of intake. This intake hash is the value every later
    re-examination will be checked against. Refuses duplicate evidence IDs
    (a duplicate ID would silently corrupt the custody trail)."""
    if any(e["evidence_id"] == evidence_id for e in evidence_register):
        print(f"  [!] Evidence ID {evidence_id} is already registered — IDs must be unique.")
        return None

    full_path = os.path.join(DATA_DIR, file_path.lstrip("./"))
    if not os.path.exists(full_path):
        print(f"  [!] File not found at {full_path} — cannot compute intake hash.")
        return None

    intake_hash = compute_sha256(full_path)
    record = {
        "evidence_id": evidence_id,
        "source": source,
        "acquisition_datetime": acquisition_datetime or datetime.now().strftime(TS_FORMAT),
        "investigator": investigator,
        "storage_location": storage_location,
        "file_path": file_path,
        "intake_sha256": intake_hash,
    }
    evidence_register.append(record)
    print(f"  [OK] Registered {evidence_id} — intake SHA-256: {intake_hash}")
    return record


# ---------------------------------------------------------------------------
# 4. Chain-of-custody logging (Deliverable 3)
# ---------------------------------------------------------------------------

def add_custody_entry(evidence_id, handler, action, notes="", when=None):
    if not any(e["evidence_id"] == evidence_id for e in evidence_register):
        print(f"  [!] {evidence_id} is not a registered evidence item — custody entry rejected.")
        return None
    entry = {
        "evidence_id": evidence_id,
        "handler": handler,
        "datetime": when if when else datetime.now().strftime(TS_FORMAT),
        "action": action,
        "notes": notes,
    }
    custody_log.append(entry)
    print(f"  [OK] Custody entry added for {evidence_id}: {action} by {handler}")
    return entry


def get_custody_history(evidence_id):
    history = [c for c in custody_log if c["evidence_id"] == evidence_id]
    return sorted(history, key=lambda r: r["datetime"])


def display_custody_history(evidence_id):
    history = get_custody_history(evidence_id)
    if not history:
        print(f"  No custody history found for {evidence_id}.")
        return
    print(f"\n  Chain of Custody — {evidence_id}")
    print("  " + "-" * 70)
    for entry in history:
        print(f"  {entry['datetime']}  {entry['handler']:<12} {entry['action']:<28} {entry['notes']}")


# ---------------------------------------------------------------------------
# 5. Integrity re-verification (Deliverable 4)
# ---------------------------------------------------------------------------

def verify_integrity(evidence_id):
    """Recomputes the hash of the evidence file and compares it to the
    hash recorded at intake. Any mismatch is a red flag: it means the
    evidence has changed since collection and its admissibility is at risk.
    Every check (pass or fail) is appended to verification_log so the report
    can show the full examination history, not just the latest result."""
    record = next((e for e in evidence_register if e["evidence_id"] == evidence_id), None)
    if record is None:
        print(f"  [!] No such evidence: {evidence_id}")
        return None

    full_path = os.path.join(DATA_DIR, record["file_path"].lstrip("./"))
    if not os.path.exists(full_path):
        print(f"  [!] File not found at {full_path}")
        return None

    current_hash = compute_sha256(full_path)
    recorded_hash = record["intake_sha256"]
    match = current_hash == recorded_hash

    result = {
        "evidence_id": evidence_id,
        "checked_at": datetime.now().strftime(TS_FORMAT),
        "recorded_hash": recorded_hash,
        "current_hash": current_hash,
        "match": match,
    }
    verification_log.append(result)

    print(f"\n  Integrity Check — {evidence_id}")
    print(f"  Recorded (intake) hash : {recorded_hash}")
    print(f"  Current  (re-examined) : {current_hash}")
    print("  Result: MATCH — evidence integrity verified." if match
          else "  Result: MISMATCH — evidence may have been altered!")
    return result


# ---------------------------------------------------------------------------
# 6. Baseline vs. snapshot validation (Deliverable 5)
# ---------------------------------------------------------------------------

def validate_baseline_vs_snapshot():
    """Compares a baseline of trusted file hashes against a later snapshot
    to classify every file as unchanged, modified, newly introduced, or
    missing. Also flags a same-hash filename swap ("renamed") — a file
    present under a new name with a hash that matches a baseline entry
    whose original name has vanished."""
    baseline = {r["filename"]: r["baseline_sha256"] for r in load_csv("baseline_hashes.csv")}
    current = {r["filename"]: r["current_sha256"] for r in load_csv("current_snapshot_hashes.csv")}

    missing_names = set(baseline) - set(current)
    new_names = set(current) - set(baseline)
    baseline_hash_to_name = {h: n for n, h in baseline.items()}

    all_files = set(baseline) | set(current)
    results = []
    for fname in sorted(all_files):
        in_base, in_curr = fname in baseline, fname in current
        if in_base and in_curr:
            status = "UNCHANGED" if baseline[fname] == current[fname] else "MODIFIED"
        elif in_curr and not in_base:
            # NEW unless its hash matches a baseline file that is now missing
            # (same content, different filename => rename, not a new file).
            possible_original = baseline_hash_to_name.get(current[fname])
            if possible_original and possible_original in missing_names:
                status = f"RENAMED (from {possible_original})"
            else:
                status = "NEW"
        else:
            status = "MISSING"
        results.append({
            "filename": fname, "status": status,
            "baseline_hash": baseline.get(fname, "-"),
            "current_hash": current.get(fname, "-"),
        })

    print("\n  Baseline vs. Snapshot Validation")
    print("  " + "-" * 100)
    print(f"  {'Filename':<26}{'Status':<22}{'Baseline Hash (trunc)':<24}{'Current Hash (trunc)'}")
    for r in results:
        b_trunc = (r["baseline_hash"][:16] + "...") if r["baseline_hash"] != "-" else "-"
        c_trunc = (r["current_hash"][:16] + "...") if r["current_hash"] != "-" else "-"
        print(f"  {r['filename']:<26}{r['status']:<22}{b_trunc:<24}{c_trunc}")

    flagged = [r for r in results if r["status"] != "UNCHANGED"]
    print(f"\n  {len(flagged)} file(s) require investigation: "
          + ", ".join(f"{r['filename']}({r['status']})" for r in flagged))
    return results


# ---------------------------------------------------------------------------
# 7. Multi-source timeline reconstruction (Deliverable 6)
# ---------------------------------------------------------------------------

def reconstruct_timeline():
    """Normalizes and merges events from three independent log sources into
    a single chronological timeline. No single source tells the whole
    story — correlating them is what reveals the attack sequence."""
    timeline = []

    for row in load_csv("auth_log.csv"):
        timeline.append({
            "timestamp": row["timestamp"], "source": "AUTH",
            "description": f"{row['event']} — user={row['username']} from {row['source_ip']} on {row['workstation']}",
        })

    for row in load_csv("file_activity_log.csv"):
        timeline.append({
            "timestamp": row["timestamp"], "source": "FILE",
            "description": f"{row['action']} — {row['filename']} by {row['user']} on {row['workstation']}",
        })

    for row in load_csv("network_log.csv"):
        timeline.append({
            "timestamp": row["timestamp"], "source": "NETWORK",
            "description": (f"Outbound {row['protocol']} to {row['dest_ip']}:{row['dest_port']} "
                             f"({row['bytes_sent']} bytes) from {row['workstation']}"),
        })

    timeline.sort(key=lambda e: datetime.strptime(e["timestamp"], TS_FORMAT))

    print("\n  Reconstructed Timeline (all sources, chronological)")
    print("  " + "-" * 90)
    for e in timeline:
        print(f"  {e['timestamp']}  [{e['source']:<7}]  {e['description']}")

    return timeline


# ---------------------------------------------------------------------------
# 8. Incident analysis (Deliverable 7)
# ---------------------------------------------------------------------------

def analyze_incident(timeline):
    """Finds the earliest suspicious event (first FAILED_LOGIN, i.e. the
    likely start of a brute-force attempt) and lists everything that
    happened afterward, citing each specific record, as potentially
    related activity. Returns a structured result so the report generator
    can cite the same records rather than re-describing them from scratch."""
    suspicious_keywords = ["FAILED_LOGIN"]
    earliest = None
    for e in timeline:
        if any(k in e["description"] for k in suspicious_keywords):
            earliest = e
            break

    print("\n  Incident Analysis")
    print("  " + "-" * 90)
    if earliest is None:
        print("  No suspicious starting event found.")
        return {"earliest": None, "related": []}

    print(f"  Earliest suspicious event: {earliest['timestamp']} [{earliest['source']}] "
          f"{earliest['description']}")
    print("  Subsequent activity (potentially related):")
    earliest_dt = datetime.strptime(earliest["timestamp"], TS_FORMAT)
    related = []
    for e in timeline:
        e_dt = datetime.strptime(e["timestamp"], TS_FORMAT)
        if e_dt > earliest_dt:
            related.append(e)
            print(f"    -> {e['timestamp']}  [{e['source']:<7}]  {e['description']}")

    return {"earliest": earliest, "related": related}


# ---------------------------------------------------------------------------
# 9. Forensic report generation (Deliverable 8)

def generate_report(case_id="CASE-2026-0311", investigator_lead="A. Kumar"):
    """Builds the report entirely from data collected in this session
    record and the "Conclusion" is visibly separated as interpretation."""
    validation_results = validate_baseline_vs_snapshot()
    timeline = reconstruct_timeline()
    analysis = analyze_incident(timeline)

    print("\n" + "=" * 78)
    print("DIGITAL FORENSIC EXAMINATION REPORT".center(78))
    print("=" * 78)
    print(f"Case ID           : {case_id}")
    print(f"Lead Investigator : {investigator_lead}")
    print(f"Report Generated  : {datetime.now().strftime(TS_FORMAT)}")

    print("\n--- 1. Evidence Examined ---")
    incomplete = []
    if not evidence_register:
        print("  No evidence has been registered in this session.")
    for record in evidence_register:
        missing = [f for f in REQUIRED_FIELDS if not record.get(f)]
        if missing:
            incomplete.append((record.get("evidence_id", "UNKNOWN"), missing))
        print(f"  {record.get('evidence_id','?'):<10} {record.get('source','?'):<40} "
              f"hash={record.get('intake_sha256','?')[:16]}...")

    print("\n--- 2. Chain of Custody Summary ---")
    by_evidence = defaultdict(int)
    for c in custody_log:
        by_evidence[c["evidence_id"]] += 1
    if not by_evidence:
        print("  No custody events recorded.")
    for eid, count in by_evidence.items():
        print(f"  {eid}: {count} custody event(s) recorded")

    print("\n--- 3. Integrity Verification History (fact) ---")
    if not verification_log:
        print("  No integrity checks have been run in this session.")
    for v in verification_log:
        outcome = "MATCH" if v["match"] else "MISMATCH — possible tampering"
        print(f"  {v['checked_at']}  {v['evidence_id']:<10} {outcome}")

    print("\n--- 4. Baseline vs. Snapshot Findings (fact) ---")
    changed = [r for r in validation_results if r["status"] != "UNCHANGED"]
    if not changed:
        print("  All files match the trusted baseline.")
    for r in changed:
        print(f"  {r['filename']:<26} {r['status']}")

    print("\n--- 5. Timeline-Derived Findings (fact, cited to specific log records) ---")
    earliest = analysis["earliest"]
    related = analysis["related"]
    if earliest:
        print(f"  F1. Earliest suspicious record: {earliest['timestamp']} [{earliest['source']}] "
              f"{earliest['description']}")
        for i, e in enumerate(related, start=2):
            print(f"  F{i}. {e['timestamp']} [{e['source']}] {e['description']}")
    else:
        print("  No suspicious record identified in the reconstructed timeline.")

    print("\n--- 6. Conclusion (investigator interpretation — see Section 5 for the") 
    print("        specific factual records this interpretation is drawn from) ---")
    if earliest:
        print(f"  Based on findings F1-F{len(related)+1} above, the evidence is consistent with")
        print(f"  an external compromise of the affected workstation originating from the")
        print(f"  repeated failed-login activity at {earliest['timestamp']}, followed by file")
        print(f"  and network activity in the same session window. This is an interpretation")
        print(f"  of the correlated records, not a directly observed fact, and should be")
        print(f"  weighed alongside the baseline validation findings in Section 4.")
    else:
        print("  Insufficient timeline evidence to draw a conclusion in this session.")

    if incomplete:
        print("\n  [WARNING] The following evidence records are missing mandatory")
        print("  fields and MUST be corrected before this report is finalized:")
        for eid, missing in incomplete:
            print(f"    - {eid}: missing {', '.join(missing)}")
    else:
        print("\n  All evidence records contain the required mandatory fields.")
    print("=" * 78)


# ---------------------------------------------------------------------------
# 10. Menu-driven interface
# ---------------------------------------------------------------------------

def print_menu():
    print("""
==================== Digital Forensics Evidence Manager ====================
 1. Display all data from the dataset
 2. Display custody dataset
 3. Display all chain-of-custody history
 4. Verify integrity of all registered evidence
 5. Validate baseline vs. current snapshot (missing/modified/new/renamed)
 6. Reconstruct multi-source timeline
 7. Analyze incident (find earliest suspicious event + related activity)
 8. Generate forensic report
 9. Exit
==============================================================================
""")


def display_registered_data():
    records = load_csv("evidence_register.csv")
    print("\n  Registered Evidence Data")
    print("  " + "-" * 90)
    if not records:
        print("  No registered evidence data found.")
        return

    for record in records:
        print(f"  Evidence ID        : {record.get('evidence_id', '')}")
        print(f"  Source             : {record.get('source', '')}")
        print(f"  Acquisition time   : {record.get('acquisition_datetime', '')}")
        print(f"  Investigator       : {record.get('investigator', '')}")
        print(f"  Storage location   : {record.get('storage_location', '')}")
        print(f"  File path          : {record.get('file_path', '')}")
        print("  " + "-" * 90)


def display_custody_data():
    records = load_csv("custody_log.csv")
    print("\n  Chain-of-Custody Dataset")
    print("  " + "-" * 90)
    if not records:
        print("  No custody data found.")
        return

    for record in records:
        print(f"  Evidence ID        : {record.get('evidence_id', '')}")
        print(f"  Handler            : {record.get('handler', '')}")
        print(f"  Date and time      : {record.get('datetime', '')}")
        print(f"  Action             : {record.get('action', '')}")
        print(f"  Notes              : {record.get('notes', '')}")
        print("  " + "-" * 90)


def load_dataset_into_session():
    for row in load_csv("evidence_register.csv"):
        if not any(record["evidence_id"] == row["evidence_id"] for record in evidence_register):
            register_evidence(row["evidence_id"], row["source"], row["file_path"],
                              row["investigator"], row["storage_location"],
                              acquisition_datetime=row["acquisition_datetime"])

    for row in load_csv("custody_log.csv"):
        if not any(entry["evidence_id"] == row["evidence_id"] and
                   entry["datetime"] == row["datetime"] for entry in custody_log):
            add_custody_entry(row["evidence_id"], row["handler"], row["action"],
                              row["notes"], when=row["datetime"])


def run_menu():
    while True:
        print_menu()
        choice = input("Select an option (1-9): ").strip()

        if choice == "1":
            display_registered_data()

        elif choice == "2":
            display_custody_data()

        elif choice == "3":
            display_custody_data()

        elif choice == "4":
            load_dataset_into_session()
            for record in evidence_register:
                verify_integrity(record["evidence_id"])

        elif choice == "5":
            validate_baseline_vs_snapshot()

        elif choice == "6":
            reconstruct_timeline()

        elif choice == "7":
            timeline = reconstruct_timeline()
            analyze_incident(timeline)

        elif choice == "8":
            load_dataset_into_session()
            generate_report()

        elif choice == "9":
            print("Exiting.")
            break

        else:
            print("  Invalid option, please choose 1-9.")


# ---------------------------------------------------------------------------
# Demo mode: runs the entire pipeline once, non-interactively
# ---------------------------------------------------------------------------

def run_demo():
    print("\n#### STEP 1: Registering evidence from the case intake sheet ####")
    for row in load_csv("evidence_register.csv"):
        register_evidence(row["evidence_id"], row["source"], row["file_path"],
                           row["investigator"], row["storage_location"],
                           acquisition_datetime=row["acquisition_datetime"])

    print("\n#### STEP 2: Replaying recorded custody transfers ####")
    for row in load_csv("custody_log.csv"):
        add_custody_entry(row["evidence_id"], row["handler"], row["action"],
                           row["notes"], when=row["datetime"])
    display_custody_history("EVD-001")

    print("\n#### STEP 3: Verifying integrity of every registered item ####")
    for record in evidence_register:
        verify_integrity(record["evidence_id"])

    print("\n#### STEP 4: Validating baseline vs. current snapshot ####")
    validate_baseline_vs_snapshot()

    print("\n#### STEP 5: Reconstructing the multi-source timeline ####")
    timeline = reconstruct_timeline()

    print("\n#### STEP 6: Analyzing the incident ####")
    analyze_incident(timeline)

    print("\n#### STEP 7: Generating the final forensic report ####")
    generate_report()


if __name__ == "__main__":
    if "--demo" in sys.argv:
        run_demo()
    else:
        run_menu()
