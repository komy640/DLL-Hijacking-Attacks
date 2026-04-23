# DLL Hijacking Attacks: 

---

## Table of Contents

1. [What Is a DLL?](#what-is-a-dll)
2. [How Windows Loads DLLs](#how-windows-loads-dlls)
3. [The DLL Search Order](#the-dll-search-order)
4. [What Is DLL Hijacking?](#what-is-dll-hijacking)
5. [The Four Types of DLL Hijacking](#the-four-types-of-dll-hijacking)
   - [Search Order Hijacking](#1-search-order-hijacking)
   - [Phantom DLL Hijacking](#2-phantom-dll-hijacking)
   - [DLL Side-Loading](#3-dll-side-loading)
   - [Relative Path DLL Hijacking](#4-relative-path-dll-hijacking)
6. [Why Attackers Love DLL Hijacking](#why-attackers-love-dll-hijacking)
7. [Real-World Examples](#real-world-examples)
8. [Detection and Forensic Analysis](#detection-and-forensic-analysis)
9. [Summary Comparison Table](#summary-comparison-table)

---

## What Is a DLL?

A **Dynamic Link Library (DLL)** is a file containing code and data that multiple
programs can use simultaneously. Rather than each program carrying its own copy of
common functions — like drawing a window, connecting to the internet, or reading a
file — Windows allows programs to share these functions through DLLs.

**Common examples of DLLs include:**
- `kernel32.dll` — core Windows functions (memory management, I/O)
- `user32.dll` — user interface functions (windows, menus, dialogs)
- `ws2_32.dll` — network and socket operations

DLLs are loaded **dynamically at runtime**, meaning a program does not need to know
exactly where a DLL lives on disk at the time it is compiled — it just knows the name.
Windows handles finding the actual file.

---

## How Windows Loads DLLs

When a Windows executable (`.exe`) starts and requests a DLL, the OS only receives
the **name** of the DLL — for example, `ntshrui.dll` — not the full path.
The **first match wins** — Windows loads that file immediately and stops searching,
regardless of whether it is legitimate or malicious.

A Windows registry key called **KnownDLLs** hardcodes a small list of critical DLL
locations — but it covers only a fraction of all DLLs, leaving the vast majority
vulnerable.

---

## The DLL Search Order

When `SafeDllSearchMode` is enabled (default on all modern Windows):

| Priority | Location |
|----------|----------|
| 1 | DLLs already loaded in memory |
| 2 | Side-by-Side (SxS) Components |
| 3 | KnownDLLs registry list |
| 4 | **Directory from which the application was launched** |
| 5 | `C:\Windows\System32` |
| 6 | `C:\Windows\System` |
| 7 | `C:\Windows` |
| 8 | Current working directory |
| 9 | Directories listed in `%PATH%` |

> ⚠️ **Priority 4** is checked *before* trusted system folders. Whoever controls
> a file with the right name in the application's folder controls what code runs.

---

## What Is DLL Hijacking?

**DLL Hijacking** is a class of attack where an adversary places a malicious DLL in
a location that Windows will find before — or instead of — the legitimate one.

### Three Primary Goals

| Goal | Description |
|------|-------------|
| **Persistence** | Malicious DLL loads every time the target app runs, including after reboots |
| **Privilege Escalation** | If the target runs as SYSTEM/Admin, attacker code inherits those privileges |
| **Defense Evasion** | Code runs inside a legitimate trusted process, hiding malicious activity |

---

## The Four Types of DLL Hijacking

### 1. Search Order Hijacking

**Concept:** Place a malicious DLL earlier in the search path than the legitimate one.

**Requirements:**
- Target `.exe` is **not** in `System32`
- The DLL it loads is **not** on the KnownDLLs list

**Classic Example — `Explorer.exe` + `ntshrui.dll`:**

```
C:\Windows\Explorer.exe          ← loads ntshrui.dll
C:\Windows\ntshrui.dll           ← ✅ ATTACKER DROPS HERE (Priority 4)
C:\Windows\System32\ntshrui.dll  ← legitimate file (Priority 5, never reached)
```

Windows checks `C:\Windows\` first (the app's directory), so the malicious DLL
is executed every time the Windows desktop starts — i.e., every user login.

> 🔒 **Why it won't be fixed:** Rooted in backward compatibility since Windows 2000.
> Changing the search order would break thousands of legacy applications.

---

### 2. Phantom DLL Hijacking

**Concept:** Some old applications try to load DLLs that **no longer exist** on
modern Windows. Provide a malicious file with that missing name.

**How it works:**
1. Identify an app that tries to load a non-existent DLL (many are publicly documented)
2. Create a malicious DLL with that exact filename
3. Place it anywhere in the search path
4. The app loads it on next execution — no legitimate version exists to compete with

**Variant — DLL Replacement:**

```
C:\Windows\System32\fxsst.dll  ← replaced with trojanized version
```

The legacy Fax Service DLL `fxsst.dll` is still attempted to be loaded by some
applications even when fax functionality is absent. Documented by Mandiant and
still actively exploited in the wild.

---

### 3. DLL Side-Loading

**Concept:** Abuse Windows **Side-by-Side (SxS)** assembly loading to introduce
a malicious DLL alongside a *trusted, signed* executable.

**How it works:**
1. Find a legitimate, digitally signed executable that uses SxS loading
2. Craft a malicious DLL
3. Write a manifest pointing the legitimate executable to the malicious DLL
4. Drop all files together — the signed binary loads the evil DLL at runtime

**Why this is uniquely dangerous:**

| Property | Effect |
|----------|--------|
| Legitimate executable is signed | Hash appears in NSRL known-good database |
| AV/EDR trusts the host process | Malicious DLL activity may not be flagged |
| Payload may never touch disk as `.exe` | Encrypted blob assembled in memory |

**PlugX — Definitive Example:**

```
legitimate_signed.exe   ← trusted, signed, triggers SxS load
malicious_loader.dll    ← attacker's DLL, loaded via SxS manifest
encrypted_payload.dat   ← decrypted and assembled in memory at runtime
```

PlugX drops all three files. The actual malicious code only exists as an encrypted
blob on disk — assembled in memory at runtime, evading most signature-based detection.
Also used by: **NetTraveler**, and many other state-sponsored RATs.

---

### 4. Relative Path DLL Hijacking (a.k.a. "Bring Your Own Executable")

**Concept:** Copy a vulnerable system binary to a *writable* location you control,
then drop a malicious DLL next to it. No write access to protected folders needed.

**Steps:**
```
1. Copy:  C:\Windows\System32\vulnerable.exe  →  C:\ProgramData\vulnerable.exe
2. Drop:  C:\ProgramData\malicious.dll         (named what vulnerable.exe expects)
3. Run:   C:\ProgramData\vulnerable.exe        (loads DLL from its own directory)
```

**Real-World Example — APT32 / OceanLotus:**

```
C:\ProgramData\mcoemcpy.exe   ← legitimate, signed McAfee binary (copied here)
C:\ProgramData\McUtil.dll     ← malicious DLL dropped by attacker
```

> ℹ️ Hundreds of Windows system binaries are vulnerable to this technique.

**Known users:** APT32 (OceanLotus), Poison Ivy variants, PlugX variants

---

## Why Attackers Love DLL Hijacking

**No Registry Modification Required**
> Unlike `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and similar keys,
> DLL hijacking leaves no registry footprint — bypassing a common monitored tripwire.

**Runs Inside Legitimate Processes**
> Network connections and file access appear to originate from trusted host processes,
> making behavioral detection significantly harder.

**Survives Reboots Naturally**
> If the hijacked app runs at startup (e.g., `Explorer.exe`), the malicious DLL
> is executed automatically on every boot with no additional attacker configuration.

**Works Across Privilege Levels**
> Depending on the target executable, execution can range from standard user level
> all the way up to SYSTEM — useful at multiple stages of an attack.

---

## Real-World Examples

| Threat Actor / Malware | Technique | Target Executable | Malicious DLL |
|---|---|---|---|
| OceanLotus / APT32 | Relative Path | `mcoemcpy.exe` (McAfee) | `McUtil.dll` |
| PlugX RAT | DLL Side-Loading | Various signed binaries | Custom loader DLL |
| NetTraveler | DLL Side-Loading | Various signed binaries | Custom loader DLL |
| Unknown (Mandiant) | Search Order Hijacking | `Explorer.exe` | `ntshrui.dll` |
| Unknown (Mandiant) | Phantom / Replacement | System applications | `fxsst.dll` |

---

## Detection and Forensic Analysis

### 🗂️ File System Timeline Analysis

Nearly every DLL hijack drops new files onto disk. On healthy systems, new DLLs
outside standard installation paths are rare. Look for:

- New `.dll` / `.exe` files in `ProgramData`, `AppData`, `Temp`, `C:\Windows\` root
- Unsigned DLLs in system-like locations
- File creation timestamps that cluster around a time of interest
- New file groupings (especially sets of 2–3 files appearing together)

### 🧠 Memory Forensics

All code running in Windows must originate from disk. Enumerate loaded DLLs per
process and check the **actual load path**:

```
SUSPICIOUS:  kernel32.dll  loaded from  C:\Users\Attacker\AppData\
EXPECTED:    kernel32.dll  loaded from  C:\Windows\System32\
```

Tools: Volatility, Rekall, Process Hacker, PE-sieve

### 📡 Behavioral Indicators

Hijacked DLLs almost always take further action. Any of the following from an
unexpected process should trigger investigation:

- Outbound network connections to unusual IPs from `Explorer.exe`, `svchost.exe`, etc.
- Code injection into other processes
- Named pipe creation
- Child processes spawned from unexpected parents

### 🔍 Why Obscure DLLs Are Preferred Targets

Common DLLs like `kernel32.dll` are almost always **already in memory** when any
application starts. Windows checks memory first (Priority 1) — so a malicious
disk copy would never be loaded. Attackers therefore target **less common DLLs**
unlikely to be pre-loaded, which means: an obscure DLL in an unusual location
is itself a strong indicator of compromise.

---

## Summary Comparison Table

| Attack Type | Needs Write to System Folder | Uses Signed Binary | DLL Must Pre-Exist | Primary Goal |
|---|---|---|---|---|
| Search Order Hijacking | Sometimes | No | Yes (in System32) | Persistence, Execution |
| Phantom DLL Hijacking | No | No | No (missing) | Persistence, Execution |
| DLL Side-Loading | No | Yes | No | Evasion, Persistence |
| Relative Path Hijacking | No | No | Yes (copied) | Evasion, Persistence, Escalation |

---

## Key Takeaways

- DLL hijacking exploits Windows' **runtime DLL search behavior** — a design rooted
  in backward compatibility with no fix on the horizon
- Four distinct variants exist, each with different requirements and stealth levels
- The attack simultaneously achieves **persistence, privilege escalation, and evasion**
  — often using entirely legitimate, signed files
- It is **detectable** through file system timelining, memory forensics, and behavioral
  monitoring — new DLLs in unexpected locations are a high-priority lead
