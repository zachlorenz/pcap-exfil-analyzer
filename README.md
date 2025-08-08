# PCAP Exfil Analyzer

**Author:** Zach Lorenz  
**Clearance:** TS/SCI (Eligible for Full Scope Polygraph)  
**Training:** Joint Cyber Analysis Course (JCAC) Graduate, 2025

---

## 📌 Overview

`pcap-exfil-analyzer` is a Python-based network analysis tool designed to identify **potential data exfiltration over DNS** from packet capture (`.pcap`) files.  

The tool uses:
- **PyShark** for packet parsing
- **Shannon entropy analysis** to detect encoded/randomized domains
- **Length-based heuristics** for long suspicious queries
- **JSON reporting** for analyst-ready output

This project is inspired by real-world **Digital Network Exploitation Analyst (DNEA)** workflows — mapping network traffic, spotting anomalies, and producing actionable intelligence.

---

## ✨ Features

- Parse PCAP files and filter DNS traffic
- Flag suspicious queries based on:
  - Query length thresholds
  - High-entropy labels (possible encoded data)
- Output detailed JSON report with:
  - Total DNS queries
  - Count and list of suspicious queries
  - Reasons each query was flagged
- Modular structure for future protocol analysis (HTTP, ICMP, etc.)

---

## 🛠 Installation

### 1. Clone the Repository
```bash
git clone git@github.com:zachlorenz/pcap-exfil-analyzer.git
cd pcap-exfil-analyzer
2. Create a Virtual Environment
python3 -m venv venv
source venv/bin/activate
3. Install Dependencies
pip install -r requirements.txt
📂 Repository Structure
pcap-exfil-analyzer/
├── run_analyzer.py         # Main CLI script
├── analyzer/
│   ├── dns_exfil.py        # DNS exfiltration detection logic
│   ├── utils.py            # Entropy calculation and helper functions
│   └── __init__.py
├── example/                # Sample PCAPs (synthetic)
├── docs/                   # Documentation and diagrams
└── requirements.txt
🚀 Usage
Basic Packet Summary
python run_analyzer.py example/sample.pcap
DNS Exfiltration Analysis
python run_analyzer.py example/sample.pcap --dns
Example Output
[+] Scanning DNS packets in: example/sample.pcap
DNS Query: google.com
[!] Suspicious DNS Query: longrandomstringdomainabc123.com (Length=64, Entropy>4.5)
...
[+] Finished. Total DNS queries: 38
[+] Suspicious queries: 4
[+] Report saved to dns_report.json
📊 Example JSON Report
{
    "file_analyzed": "example/sample.pcap",
    "total_queries": 38,
    "suspicious_count": 4,
    "suspicious_queries": [
        {
            "query": "longrandomstringdomainabc123.com",
            "length": 64,
            "entropy_labels": ["longrandomstringdomainabc123"],
            "reasons": ["Length=64", "Entropy>4.5"]
        }
    ],
    "analysis_time": "2025-08-07T14:42:30.102Z"
}
🔮 Roadmap
HTTP POST data exfiltration detection

ICMP covert channel detection

CSV output option

Beaconing pattern detection

📜 License
This project is licensed under the MIT License. See LICENSE for details.

🛡️ Disclaimer
All PCAPs and data used in this repository are synthetic and generated for training purposes.
No classified or sensitive data is included.
