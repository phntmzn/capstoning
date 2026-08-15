# capstoning

A collection of Python experiments for **macOS binary analysis, process inspection, package security checks, DNS monitoring, and malware-analysis research**.

The project focuses on understanding macOS internals from Python, including Mach-O parsing, Capstone-powered ARM64 disassembly, process architecture detection, framework/dependency inspection, notarization checks, and defensive network monitoring.

The repository currently contains standalone scripts rather than a single monolithic application. ([GitHub](https://github.com/phntmzn/capstoning/tree/main))

## Features

### Mach-O parsing and disassembly

`cap.py` parses Mach-O binaries, detects universal/FAT binaries, selects an ARM64 slice, reads Mach-O headers and sections, and uses the Capstone framework for disassembly. The current script targets the Messages executable by default and includes handling for both `x86_64` and `arm64` CPU types. ([GitHub](https://github.com/phntmzn/capstoning/blob/main/cap.py))

```text
Universal Mach-O
      │
      ├── x86_64
      │
      └── arm64
            │
            ▼
      Mach-O header
            │
            ▼
        Sections
            │
            ▼
         __text
            │
            ▼
        Capstone
            │
            ▼
     ARM64 assembly
```

### Process architecture detection

`executionarchitecture.py` interfaces with native macOS APIs through Python's `ctypes`.

It uses:

- `sysctlnametomib()`
- `sysctl()`
- `CPU_TYPE_X86_64`
- `CPU_TYPE_ARM64`
- `P_TRANSLATED`

to inspect the architecture associated with a running process. ([GitHub](https://github.com/phntmzn/capstoning/blob/main/executionarchitecture.py))

This is useful when researching the difference between:

```text
Intel / x86_64
Apple Silicon / arm64
Rosetta-translated execution
```

### Mach-O dependency extraction

`macho_dependencies.py` statically reads Mach-O load commands and extracts direct dynamic-library dependencies without executing the target binary. ([GitHub](https://github.com/phntmzn/capstoning/blob/main/macho_dependencies.py))

Supported dependency commands include:

```text
LC_LOAD_DYLIB
LC_LOAD_WEAK_DYLIB
LC_REEXPORT_DYLIB
LC_LOAD_UPWARD_DYLIB
```

This can reveal frameworks such as:

```text
/System/Library/Frameworks/Foundation.framework
/System/Library/Frameworks/AppKit.framework
/System/Library/Frameworks/DiskArbitration.framework
/usr/lib/libSystem.B.dylib
```

Dependency information can help identify functionality that deserves additional analysis.

### DiskArbitration analysis

`detect_diskarbitration.py` highlights Mach-O dependencies associated with Apple's DiskArbitration framework.

`disk_api_scan.py` performs additional static inspection for DiskArbitration-related API names.

These scripts are intended for identifying binaries that may interact with disks or removable media.

### DNS monitoring

`dns_monitor.py` uses Scapy to passively inspect DNS queries and responses.

The monitor:

- captures DNS traffic on port 53
- handles IPv4 and IPv6
- extracts queried domains
- records DNS responses
- writes historical events to `dns_events.jsonl`
- applies simple heuristics to unusual DNS names

The implementation imports Scapy's `sniff`, `DNS`, `DNSQR`, `DNSRR`, `IP`, and `IPv6` components and stores events in JSON Lines format. ([GitHub](https://github.com/phntmzn/capstoning/blob/main/dns_monitor.py))

Example:

```text
[DNS QUERY] 192.168.1.20 -> 192.168.1.1 example.com

[DNS RESPONSE] 192.168.1.1 -> 192.168.1.20
    example.com -> 93.184.216.34
```

### Package notarization

`package_notarization.py` checks macOS packages using Apple's:

```bash
xcrun stapler validate
```

rather than directly depending on private notarization APIs. ([GitHub](https://github.com/phntmzn/capstoning/blob/main/package_notarization.py))

### Package security analysis

`package_security.py` combines notarization-ticket validation with a Gatekeeper assessment using:

```bash
spctl --assess --verbose=4 --type install
```

The script reports both the stapler result and whether Gatekeeper accepts the installer. ([GitHub](https://github.com/phntmzn/capstoning/blob/main/package_security.py))

## Repository layout

```text
capstoning/
├── cap.py
├── dazzlespylab.md
├── detect_diskarbitration.py
├── disk_api_scan.py
├── dns_monitor.py
├── executionarchitecture.py
├── macho_dependencies.py
├── package_notarization.py
└── package_security.py
```

These files are currently present on the `main` branch. ([GitHub](https://github.com/phntmzn/capstoning/tree/main))

## Requirements

This project is intended for **macOS**.

Recommended:

```text
macOS
Python 3
Xcode Command Line Tools
```

Python dependencies used by the current scripts include:

```text
capstone
scapy
```

Install them with:

```bash
python3 -m pip install capstone scapy
```

`cap.py` imports the Capstone Python bindings directly. ([GitHub](https://github.com/phntmzn/capstoning/blob/main/cap.py)) `dns_monitor.py` depends on Scapy. ([GitHub](https://github.com/phntmzn/capstoning/blob/main/dns_monitor.py))

For the package-security scripts, ensure Apple's developer command-line tools are available:

```bash
xcode-select --install
```

## Installation

Clone the repository:

```bash
git clone https://github.com/phntmzn/capstoning.git
cd capstoning
```

Optionally create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the Python packages:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install capstone scapy
```

## Usage

### ARM64 Mach-O disassembly

```bash
python3 cap.py
```

`cap.py` currently contains a target path directly in the script:

```python
path = "/System/Applications/Messages.app/Contents/MacOS/Messages"
```

Change this value to analyze another Mach-O file. ([GitHub](https://github.com/phntmzn/capstoning/blob/main/cap.py))

### Inspect process architecture

```bash
python3 executionarchitecture.py
```

The script uses native macOS `sysctl` interfaces to determine process CPU architecture. ([GitHub](https://github.com/phntmzn/capstoning/blob/main/executionarchitecture.py))

### Extract Mach-O dependencies

```bash
python3 macho_dependencies.py
```

Change the target path inside the script to the Mach-O you want to inspect.

The operation is static: the target program does not need to be launched. ([GitHub](https://github.com/phntmzn/capstoning/blob/main/macho_dependencies.py))

### Scan for DiskArbitration usage

```bash
python3 detect_diskarbitration.py
```

or:

```bash
python3 disk_api_scan.py
```

These scripts are useful for triaging binaries that may interact with disks, volumes, or removable media.

### Monitor DNS

Because packet capture generally requires elevated privileges on macOS:

```bash
sudo python3 dns_monitor.py
```

DNS events are written to:

```text
dns_events.jsonl
```

The configured packet filter is:

```text
port 53
```

([GitHub](https://github.com/phntmzn/capstoning/blob/main/dns_monitor.py))

### Check package notarization

Edit the package path in:

```text
package_notarization.py
```

then run:

```bash
python3 package_notarization.py
```

Internally this invokes:

```bash
xcrun stapler validate /path/to/Installer.pkg
```

([GitHub](https://github.com/phntmzn/capstoning/blob/main/package_notarization.py))

### Run full package security checks

```bash
python3 package_security.py
```

The script performs both:

```text
Notarization ticket validation
              +
      Gatekeeper assessment
```

using Apple's `stapler` and `spctl` tooling. ([GitHub](https://github.com/phntmzn/capstoning/blob/main/package_security.py))

## Example research workflow

```text
                macOS binary
                     │
                     ▼
              Detect Mach-O
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
   Inspect architecture   Parse dependencies
          │                     │
          ▼                     ▼
 ARM64 / Intel / FAT      Framework analysis
          │                     │
          ▼                     ▼
 Capstone disassembly     API / IOC scanning
          │
          ▼
      Static analysis


                 Installer.pkg
                     │
                     ▼
              stapler validate
                     │
                     ▼
              spctl assessment


                 Network
                     │
                     ▼
                DNS capture
                     │
                     ▼
              JSONL history
```

## Goals

The project is useful for learning and experimenting with:

- Mach-O internals
- ARM64 reverse engineering
- Apple Silicon architecture
- Universal binaries
- Capstone
- macOS `sysctl`
- dylib and framework dependencies
- package notarization
- Gatekeeper
- DiskArbitration analysis
- DNS-based threat hunting
- static malware analysis

## Safety

This repository is intended for **security research, education, reverse engineering, and defensive analysis**.

Run analysis tools only against systems and binaries you are authorized to inspect.

Static indicators should also be treated as evidence for investigation rather than proof that a binary is malicious. For example, linking against a particular Apple framework does not by itself demonstrate malicious behavior.

## Inspiration

Some of the experiments in this repository explore macOS malware-analysis concepts such as:

```text
Mach-O parsing
process inspection
dependency analysis
package validation
network monitoring
```

These techniques are useful for understanding both legitimate macOS software and malicious software from a defensive perspective.

## Future ideas

Potential additions:

```text
[ ] FAT64 / universal Mach-O improvements
[ ] automatic x86_64 + arm64 slice analysis
[ ] LC_RPATH extraction
[ ] LC_ID_DYLIB parsing
[ ] symbol-table parsing
[ ] imported-function analysis
[ ] Objective-C metadata parsing
[ ] code-signature inspection
[ ] entitlement extraction
[ ] SHA-256 hashing
[ ] JSON analysis reports
[ ] IOC scanning
[ ] recursive dependency inspection
[ ] richer DNS statistics
[ ] command-line arguments for target paths
```

## License

Add a license before redistributing or accepting substantial external contributions.

## Author

**phntmzn**

GitHub: `phntmzn/capstoning`
