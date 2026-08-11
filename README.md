Status: In Progress

# Security Investigation Reports

This directory contains documented Blue Team, malware analysis, threat hunting, digital forensics, and detection engineering investigations.

Each investigation is organized as a self-contained case study containing the relevant analysis, evidence, findings, indicators, and supporting artifacts.

## Investigations

### Memory Forensics Investigation

A hands-on Windows memory forensics investigation focused on identifying suspicious process activity, injected code, anomalous memory regions, loaded modules, and network artifacts from a captured memory image.

The investigation uses:

- Volatility 3
- MemProcFS
- FLARE-VM
- Procmon for supporting host telemetry

📁 [`memory-analysis/`](./memory-analysis/)

The investigation includes:

- Executive summary
- Full technical investigation
- Analyst notebook
- Execution timeline
- Findings
- Host and network IOCs
- Volatility artifacts
- MemProcFS artifacts
- Evidence integrity documentation
- Supporting screenshots

---

## Investigation Methodology

The investigations in this repository follow an evidence-driven Blue Team methodology:

```text
Investigation Question
        │
        ▼
Evidence Collection
        │
        ▼
Artifact Identification
        │
        ▼
Analysis
        │
        ▼
Cross-Tool Correlation
        │
        ▼
Finding
        │
        ▼
IOC Extraction
        │
        ▼
Detection / Response Opportunity
```
The objective is not simply to demonstrate individual security tools, but to demonstrate how security telemetry and forensic artifacts can be correlated to answer investigative questions and produce defensible findings.

---

Skills Demonstrated

The investigations demonstrate practical experience in:

* Security Operations
* Malware Analysis
* Behavioral Analysis
* Memory Forensics
* Digital Forensics
* Threat Hunting
* Windows Process Analysis
* Network Analysis
* IOC Extraction
* Evidence Correlation
* Detection Engineering
* MITRE ATT&CK Mapping
* Incident Response

---

# Repository Organization
```text
reports/
│
├── README.md
│
└── memory-analysis/
    ├── README.md
    ├── investigation-report.md
    ├── executive-summary.md
    ├── analyst-notebook.md
    ├── execution-timeline.md
    │
    └── screenshots/
        ├── volatility/
        └── procmon/
        └── memprocfs/
```

# Evidence Handling

Where applicable, investigation artifacts include:

* Cryptographic hashes
* Evidence manifests
* Raw tool output
* Analyst notes
* Screenshots
* Machine-readable IOC files

Sensitive or unnecessary malware binaries and other potentially dangerous artifacts should not be committed to the repository unless there is a specific and controlled reason to do so.

---

Disclaimer

These investigations were conducted in controlled laboratory environments for educational, research, and defensive security purposes.

The documented findings should be interpreted within the context of the associated laboratory environment and available evidence.

---

Author

Allen Ace
Blue Team / SOC Analyst

Areas of focus:

* SOC Operations
* Threat Hunting
* Malware Analysis
* DFIR
* Detection Engineering
* Security Monitoring

## Disclaimer

This repository is intended for educational, defensive security, and
authorized forensic analysis purposes only.

The investigation artifacts and techniques documented here were performed
within controlled laboratory environments. Do not apply these techniques
against systems, networks, or data without appropriate authorization.

Malware samples, memory images, credentials, or other sensitive forensic
artifacts should not be committed to this repository.