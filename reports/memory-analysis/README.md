# Windows Memory Forensics Investigation

> **Blue Team | Memory Forensics | Malware Analysis | Digital Forensics | Incident Response**

This project documents a hands-on **Windows memory forensics investigation** performed from a Blue Team / incident-response perspective.

The investigation analyzes a Windows memory image captured during suspected malware execution and demonstrates how volatile memory can be used to identify suspicious processes, executable memory regions, potential process manipulation, modified PE structures, loaded modules, and network artifacts.

The investigation combines **Volatility 3, MemProcFS, and Procmon** to develop and correlate forensic evidence.

---

# Investigation Summary

The investigation began with broad process enumeration and progressively narrowed the analysis to a suspicious instance of:

`dfsvc.exe`

The process was identified with:

`PID 5252`

Subsequent analysis identified:

- Suspicious `PAGE_EXECUTE_READWRITE` memory regions
- Volatility `malfind` findings
- MemProcFS `FindEvil` findings
- A `PE_PATCHED` condition
- Loaded modules requiring contextual review
- Network artifacts requiring further investigation
- Supporting process telemetry associated with the process execution chain

The findings were correlated across multiple evidence sources rather than treating individual tool outputs as standalone proof.

---

# Key Evidence Chain

```text
Process Enumeration
        │
        ▼
dfsvc.exe / PID 5252
        │
        ▼
Suspicious RWX Memory
        │
        ▼
Volatility malfind
        │
        ▼
MemProcFS FindEvil
        │
        ▼
PE_PATCHED
        │
        ▼
Network Artifact
        │
        ▼
Correlated Suspicion
```

**Overall Assessment**: The combined evidence is consistent with compromise or malicious manipulation of dfsvc.exe. The exact injection mechanism, malware family, persistence mechanism, and external infrastructure were not conclusively established from the available evidence.

# Objectives

The investigation was designed to demonstrate the ability to:

* Perform Windows memory forensics
* Enumerate and investigate processes
* Reconstruct process relationships
* Identify suspicious executable memory
* Investigate potential code injection
* Analyze loaded DLLs
* Extract network artifacts from memory
* Correlate evidence across forensic tools
* Extract host and network IOCs
* Develop defensible Blue Team assessments
* Identify detection and response opportunities

⸻

# Tools Used

| Tool | Purpose |
|---|---|
| Volatility 3 | Windows memory analysis |
| MemProcFS | Complementary memory and forensic artifact analysis |
| Procmon | Supporting process and host telemetry |
| FLARE-VM | Malware-analysis environment |

# Investigation Workflow

```text
Memory Image
     │
     ▼
Evidence Validation
     │
     ▼
Process Enumeration
     │
     ▼
Process Tree Analysis
     │
     ▼
Suspicious Memory Detection
     │
     ▼
Process / DLL Analysis
     │
     ▼
MemProcFS Validation
     │
     ▼
Network Artifact Analysis
     │
     ▼
Evidence Correlation
     │
     ▼
IOC Extraction
     │
     ▼
Detection / Response Opportunities
```

# Repository Structure

```text
memory-analysis/
│
├── README.md
├── investigation-report.md
├── executive-summary.md
├── analyst-notebook.md
├── execution-timeline.md
├── findings.md
│
├── iocs/
│   ├── host-iocs.csv
│   └── network-iocs.csv
│
├── volatility/
│   ├── malfind.txt
│   ├── pstree.txt
│   ├── pslist.txt
│   ├── dlllist.txt
│   └── notes.md
│
├── memprocfs/
│   ├── forensic-findevil.txt
│   ├── process-tree.txt
│   ├── netstat.txt
│   └── notes.md
│
├── evidence/
│   ├── memory-image.sha256.txt
│   └── evidence-manifest.md
│
└── screenshots/
    ├── volatility/
    └── memprocfs/
```

# Investigation Documentation

```text
Investigation Report
```
`investigation-report.md`

Contains the complete technical investigation, evidence analysis, correlation, findings, limitations, and analyst assessment.

```text
Executive Summary
```
`executive-summary.md`

Provides a concise overview of the investigation, principal findings, assessment, and recommended next steps.

```text
Analyst Notebook
```
`analyst-notebook.md`

Documents investigative reasoning, analytical pivots, observations, and decisions made during the investigation.

```text
Execution Timeline
```
`execution-timeline.md`

Provides the chronological sequence of investigative observations and evidence correlation.

```text
Findings
```
`findings.md`

Contains the formal findings, evidence references, confidence assessments, ATT&CK considerations, and detection opportunities.

⸻

```text
Volatility Evidence
```
The Volatility artifacts are preserved under:

**volatility/**

| Artifact | Purpose |
|---|---|
| `pslist.txt` | Process enumeration |
| `pstree.txt` | Process ancestry |
| `malfind.txt` | Suspicious memory detection |
| `dlllist.txt` | Loaded module analysis |
| `notes.md` | Analyst notes |


# MemProcFS Evidence

MemProcFS artifacts are preserved under:

**memprocfs/**

| Artifact | Purpose |
|---|---|
| `forensic-findevil.txt` | Suspicious memory analysis |
| `process-tree.txt` | Process relationship analysis |
| `netstat.txt` | Network artifact analysis |
| `notes.md` | Analyst notes |

# Indicators of Compromise

Extracted indicators are maintained separately from the narrative investigation.

## Host IOCs

`iocs/host-iocs.csv`

Potential host indicators include:

* Process names
* Process IDs
* File paths
* Hashes
* DLLs
* Other host artifacts

# Network IOCs

iocs/network-iocs.csv

Potential network indicators include:

* IP addresses
* Domains
* Ports
* Network connections
* Other network artifacts recovered from memory

Only indicators supported by the investigation evidence should be classified as confirmed IOCs.

⸻

# Evidence Integrity

The memory image used during the investigation is represented by its SHA256 hash.

Evidence integrity information is maintained in:

evidence/memory-image.sha256.txt

Supporting provenance information is maintained in:

evidence/evidence-manifest.md

The original memory image is not included in the repository.

⸻

# Screenshots

Screenshots are maintained as supporting evidence.

## Volatility

`screenshots/volatility/`

Contains screenshots supporting:

* Process enumeration
* Process tree analysis
* malfind
* Process extraction
* DLL analysis

# MemProcFS

`screenshots/memprocfs/`

Contains screenshots supporting:

* FindEvil
* PE modification
* Process tree
* Network artifacts

Screenshots are supporting evidence and should be interpreted alongside the corresponding raw output.

⸻

# MITRE ATT&CK

The observed behavior warrants investigation under:

## T1055 — Process Injection

The available evidence indicates possible in-memory process manipulation but does not conclusively establish a specific process-injection sub-technique.

Additional reverse engineering and endpoint telemetry would be required for more specific ATT&CK classification.

⸻

# Blue Team Skills Demonstrated

This project demonstrates practical experience in:

* Windows memory forensics
* Malware analysis
* Digital forensics
* Process investigation
* Process tree reconstruction
* Code injection investigation
* Executable memory analysis
* DLL analysis
* Network artifact analysis
* Volatility 3
* MemProcFS
* Procmon
* IOC extraction
* Evidence correlation
* Incident-response methodology
* Threat hunting
* MITRE ATT&CK mapping
* Detection engineering considerations

⸻

# Investigation Philosophy

The investigation follows an evidence-driven approach:

```text
Question
   ↓
Evidence
   ↓
Observation
   ↓
Correlation
   ↓
Assessment
   ↓
IOC
   ↓
Detection / Response
```

The objective is not simply to identify suspicious output from a forensic tool.

The objective is to determine:

What happened, what evidence supports the assessment, how confident are we, and what should a defender do next?

⸻

# Key Takeaway

Memory forensics provides visibility into artifacts that may not be available through conventional disk-based analysis alone.

By combining Volatility 3 and MemProcFS with supporting endpoint telemetry, this investigation demonstrates how a Blue Team analyst can move from an initial suspicious process to a correlated evidence set involving:

```text
Process
   +
Memory
   +
Modules
   +
Network
   +
Telemetry
   ↓
Defensible Security Assessment
```

The project demonstrates a practical approach to using volatile memory as an investigative source during malware analysis, threat hunting, and incident response.

# Disclaimer

This investigation was conducted in a controlled malware-analysis environment for educational and portfolio purposes.

The findings represent the evidence available within the analyzed memory image and supporting telemetry. Conclusions should not be generalized beyond the available evidence without additional validation.