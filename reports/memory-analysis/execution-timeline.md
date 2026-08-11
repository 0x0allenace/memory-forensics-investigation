# Execution Timeline

## Timeline Overview

This document records the chronological sequence of investigative observations and analytical pivots identified during the memory-forensics investigation.

The timeline combines memory-forensics evidence with supporting host telemetry where available.

---

# Investigation Timeline

| Stage | Activity | Evidence | Analytical Significance |
|---|---|---|---|
| 1 | Malware execution occurred in the analysis environment | Lab execution context | Generated the forensic evidence examined during the investigation |
| 2 | Memory image captured | Windows memory image | Primary forensic evidence |
| 3 | Evidence integrity validated | `evidence/memory-image.sha256.txt` | Established evidence integrity |
| 4 | Processes enumerated | `volatility/pslist.txt` | Established process population |
| 5 | `dfsvc.exe` identified | PID `5252` | Selected for targeted investigation |
| 6 | Process hierarchy reconstructed | `volatility/pstree.txt` | Investigated process ancestry |
| 7 | PPID `1188` identified | Volatility / Procmon | Parent process required additional investigation |
| 8 | PID `1188` correlated to `malz3.exe` | Procmon telemetry | Provided supporting execution context |
| 9 | Suspicious memory identified | `volatility/malfind.txt` | RWX memory increased suspicion |
| 10 | Process-specific analysis performed | `volatility/pslist.txt` | Additional process context collected |
| 11 | Process extracted from memory | Process dump | Enabled potential subsequent malware analysis |
| 12 | Loaded modules examined | `volatility/dlllist.txt` | Identified modules requiring contextual review |
| 13 | MemProcFS analysis performed | `memprocfs/` | Independent memory-analysis perspective |
| 14 | `dfsvc.exe` identified by FindEvil | `memprocfs/forensic-findevil.txt` | Corroborated suspicious-memory finding |
| 15 | `PE_PATCHED` observed | MemProcFS forensic output | Added evidence of PE modification |
| 16 | Process structure reviewed | `memprocfs/process-tree.txt` | Additional process correlation |
| 17 | Network artifacts reviewed | `memprocfs/netstat.txt` | Identified network activity requiring investigation |
| 18 | Evidence correlated | Multiple sources | Increased confidence in overall assessment |
| 19 | Findings documented | `findings.md` | Converted observations into formal findings |
| 20 | IOC artifacts documented | `iocs/` | Preserved actionable indicators |

---

# Process Investigation Sequence

```text
Malware Execution
       │
       ▼
Memory Capture
       │
       ▼
Process Enumeration
       │
       ▼
dfsvc.exe Identified
       │
       ▼
PID 5252
       │
       ▼
Process Tree Analysis
       │
       ▼
PPID 1188
       │
       ▼
Procmon Correlation
       │
       ▼
malz3.exe
```

# Memory Investigation Sequence

```text
dfsvc.exe
    │
    ▼
Volatility malfind
    │
    ▼
Suspicious RWX Memory
    │
    ▼
MemProcFS FindEvil
    │
    ▼
PE_PATCHED
    │
    ▼
Correlated Suspicion
```

# Network Investigation Sequence

```text
Suspicious Process
       │
       ▼
MemProcFS Network Artifacts
       │
       ▼
Process / Network Association
       │
       ▼
Network State Requiring Investigation
       │
       ▼
Additional Network Telemetry Recommended
```

## Timeline Limitations

The available evidence does not provide a complete timestamped reconstruction of every event occurring during execution.

Some process activity may not be represented in the memory image because processes can terminate before acquisition.

The timeline should therefore be interpreted as an investigative sequence and evidence-based reconstruction rather than a complete event-by-event attack timeline.