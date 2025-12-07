import os
import hashlib
from datetime import datetime
import platform
import re
from collections import defaultdict

# ===============================================================
# MODULE 1: FILE METADATA + HASH EXTRACTION
# ===============================================================

def compute_hashes(file_path, block_size=4096):
    """
    Computes MD5 and SHA-256 hashes for a given file.
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(block_size):
            md5.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha256.hexdigest()


def get_file_creation_time(file_path):
    """
    Cross-platform method to get file creation time.
    """
    if platform.system() == "Windows":
        return datetime.fromtimestamp(os.path.getctime(file_path))
    else:
        stats = os.stat(file_path)
        try:
            return datetime.fromtimestamp(stats.st_birthtime)
        except AttributeError:
            return datetime.fromtimestamp(stats.st_mtime)


def extract_file_metadata(file_path):
    """
    Extracts size, timestamps, and cryptographic hashes.
    """
    stats = os.stat(file_path)
    size = stats.st_size
    created = get_file_creation_time(file_path)
    modified = datetime.fromtimestamp(stats.st_mtime)

    md5_value, sha256_value = compute_hashes(file_path)

    return {
        "file_path": file_path,
        "size_bytes": size,
        "created": created,
        "modified": modified,
        "md5": md5_value,
        "sha256": sha256_value
    }


# ===============================================================
# MODULE 2: LOG FILE ANALYZER WITH BRUTE FORCE DETECTION
# ===============================================================

def analyze_log(path):
    """
    Returns suspicious log entries and brute-force detected IPs.
    """
    suspicious_entries = []
    failed_attempts = defaultdict(int)
    brute_force_ips = set()

    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    BRUTE_FORCE_THRESHOLD = 5  # 5 failed logins = brute force

    with open(path, "r", errors="ignore") as f:
        for line in f:
            line_lower = line.lower()

            if "failed" in line_lower:
                suspicious_entries.append(line.strip())

                ip_match = re.search(ip_pattern, line)
                if ip_match:
                    ip = ip_match.group()
                    failed_attempts[ip] += 1

                    if failed_attempts[ip] > BRUTE_FORCE_THRESHOLD:
                        brute_force_ips.add(ip)

    return suspicious_entries, brute_force_ips


# ===============================================================
# MODULE 3: REPORT GENERATOR
# ===============================================================

def generate_forensic_report(metadata_list, suspicious_logs, brute_force_ips, output_file="forensic_report.txt"):
    """
    Writes the full forensic report including metadata, suspicious logs,
    and brute force detection summary.
    """
    with open(output_file, "w") as rpt:
        rpt.write("=" * 60 + "\n")
        rpt.write("                FORENSIC ANALYSIS REPORT\n")
        rpt.write("=" * 60 + "\n\n")

        # FILE METADATA
        rpt.write("===== FILE METADATA & HASHES =====\n\n")
        for m in metadata_list:
            rpt.write(f"File: {m['file_path']}\n")
            rpt.write(f"Size (bytes): {m['size_bytes']}\n")
            rpt.write(f"Created: {m['created']}\n")
            rpt.write(f"Modified: {m['modified']}\n")
            rpt.write(f"MD5: {m['md5']}\n")
            rpt.write(f"SHA-256: {m['sha256']}\n")
            rpt.write("-" * 40 + "\n")

        # LOG ANALYSIS
        rpt.write("\n===== SUSPICIOUS LOG ENTRIES =====\n\n")
        if suspicious_logs:
            for entry in suspicious_logs:
                rpt.write(entry + "\n")
        else:
            rpt.write("No suspicious log entries found.\n")

        # BRUTE FORCE DETECTION
        rpt.write("\n===== BRUTE FORCE ANALYSIS =====\n\n")
        if brute_force_ips:
            rpt.write("Brute-force attack detected from:\n")
            for ip in brute_force_ips:
                rpt.write(f"- {ip}\n")
        else:
            rpt.write("No brute-force activity detected.\n")

        rpt.write("\nReport generated successfully.\n")

    return output_file


# ===============================================================
# MAIN EXECUTION
# ===============================================================

if __name__ == "__main__":
    print("\n=========== FORENSIC TOOL STARTED ===========\n")

    # ---------------------- USER FILES ----------------------------
    evidence_files = [
        "evidence_files/example1.txt",
        "evidence_files/report.pdf",
        "evidence_files/image1.jpg",
        "evidence_files/notes.txt"
    ]

    log_file = "logs/system.log.txt"

    # ---------------------- METADATA EXTRACTION -------------------
    all_metadata = []
    print(">>> Extracting file metadata...\n")

    for file in evidence_files:
        if os.path.exists(file):
            print(f"[+] Processing: {file}")
            metadata = extract_file_metadata(file)
            all_metadata.append(metadata)
        else:
            print(f"[WARNING] File not found: {file}")

    # ---------------------- LOG ANALYSIS --------------------------
    print("\n>>> Analyzing logs...\n")

    if os.path.exists(log_file):
        suspicious_logs, brute_force_ips = analyze_log(log_file)

        if brute_force_ips:
            print("[!] Brute-force attack detected from:")
            for ip in brute_force_ips:
                print(f"     → {ip}")
        else:
            print("[+] No brute-force patterns detected.")

    else:
        suspicious_logs = []
        brute_force_ips = set()
        print(f"[WARNING] Log file not found: {log_file}")

    # ---------------------- REPORT GENERATION ---------------------
    print("\n>>> Generating forensic report...\n")
    report_path = generate_forensic_report(all_metadata, suspicious_logs, brute_force_ips)
    print(f"[+] Forensic report successfully created: {report_path}\n")
