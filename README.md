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
