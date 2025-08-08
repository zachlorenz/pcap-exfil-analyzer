# analyzer/dns_exfil.py

import pyshark
import json
from datetime import datetime
from analyzer.utils import calculate_entropy

def analyze_dns(file_path, suspicious_length=50, entropy_threshold=4.5, report_file="dns_report.json"):
    print(f"[+] Scanning DNS packets in: {file_path}")
    capture = pyshark.FileCapture(file_path, display_filter="dns")

    total_queries = 0
    suspicious_queries = []

    for packet in capture:
        try:
            query_name = packet.dns.qry_name
            total_queries += 1

            # Suspicion checks
            length_flag = len(query_name) > suspicious_length
            labels = query_name.split(".")
            high_entropy_labels = [
                label for label in labels if calculate_entropy(label) > entropy_threshold
            ]
            entropy_flag = len(high_entropy_labels) > 0

            # Build result entry
            if length_flag or entropy_flag:
                reason = []
                if length_flag:
                    reason.append(f"Length={len(query_name)}")
                if entropy_flag:
                    reason.append(f"Entropy>{entropy_threshold}")
                print(f"[!] Suspicious DNS Query: {query_name} ({', '.join(reason)})")
                suspicious_queries.append({
                    "query": query_name,
                    "length": len(query_name),
                    "entropy_labels": high_entropy_labels,
                    "reasons": reason
                })
            else:
                print(f"DNS Query: {query_name}")

        except AttributeError:
            continue

    # Write JSON report
    report_data = {
        "file_analyzed": file_path,
        "total_queries": total_queries,
        "suspicious_count": len(suspicious_queries),
        "suspicious_queries": suspicious_queries,
        "analysis_time": datetime.now().isoformat()
    }

    with open(report_file, "w") as f:
        json.dump(report_data, f, indent=4)

    print(f"\n[+] Finished. Total DNS queries: {total_queries}")
    print(f"[+] Suspicious queries: {len(suspicious_queries)}")
    print(f"[+] Report saved to {report_file}")

    return suspicious_queries
