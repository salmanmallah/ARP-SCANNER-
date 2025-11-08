# ARP Scanner — concise

Simple ARP-based LAN scanner (IP ↔ MAC) using Scapy.

Provides automatic interface selection, optional manual interface choice, configurable timeout/retries, and optional output to TXT/PDF.
# ARP Scanner

A small, cross-platform ARP network scanner built with Scapy.

This tool sends ARP requests on your local network to discover active devices and prints IP ↔ MAC mappings.

---

## Features

- ARP-based network discovery (Layer 2)
- Automatic interface selection for the target network
- Optional `-i/--iface` to pick an interface manually
- `--list-ifaces` to show available Scapy interfaces (NPF keys, friendly names, MACs)
- Configurable `--timeout` and `--retries` to tune discovery reliability
- Friendly error messages for missing dependencies and common Windows issues (Npcap, permissions)

---

## Requirements

- Python 3.8+
# ARP Scanner

Lightweight ARP network scanner using Scapy. It discovers devices on a local Ethernet/Wi‑Fi LAN by sending ARP requests and collecting replies (IP ↔ MAC mappings).

This repository contains a small, easy-to-run scanner (`main.py`) with a few helpful features:

- automatic interface selection for the target network
- optional manual interface selection (`-i`)
- `--list-ifaces` to show available interfaces
- configurable `--timeout` and `--retries`
- optional save to TXT or PDF (`-o` / `--format`)

---

## Quick start

1. (Optional) Activate your virtualenv if you use one:

```bash
source myenv/bin/activate  # or myenv\Scripts\activate on Windows
```

2. Run the scanner:

```bash
python main.py -t 192.168.100.0/24
```

3. Save output (TXT or PDF):

```bash
python main.py -t 192.168.100.0/24 -o scan_output.pdf
```

Recommended: use the included virtual environment (`myenv`) or create your own.

Activate the venv (example for Git Bash / WSL):

```bash
source myenv/bin/activate
```

Run a simple scan (example):

```bash
myenv/Scripts/python.exe main.py -t 192.168.100.0/24
```

Run and save results to a PDF (requires reportlab in the active environment):

```bash
myenv/Scripts/python.exe main.py -t 192.168.100.0/24 -o scan_output.pdf
```

If `reportlab` is missing the tool will save TXT instead and print a notice.

---

## Usage (essential options)

- `-t, --target` (required): target IP or subnet, e.g. `192.168.1.1/24`
- `-i, --iface` (optional): interface (NPF key or friendly name)
- `--list-ifaces`: list available interfaces
- `--timeout`: seconds to wait per attempt (default 2.0)
- `--retries`: ARP attempts to perform and aggregate replies (default 2)
- `-o, --output`: output filename (use `.pdf` or `.txt` to select format)
- `--format`: explicitly choose `txt` or `pdf`

Example:

```bash
python main.py -t 192.168.100.0/24 --retries 3 --timeout 2 -o scan_output.pdf
```

- `-t, --target` (required): target IP or subnet, e.g. `192.168.1.1/24`
- `-i, --iface` (optional): explicit interface (NPF key or friendly name)
- `--list-ifaces`: print available interfaces (NPF key → friendly name → MAC)
- `--timeout`: seconds to wait per attempt (default 2.0)
- `--retries`: number of ARP attempts to perform and aggregate replies (default 2)
- `-o, --output`: optional output file (use `.pdf` or `.txt` extension)
- `--format`: explicit output format (`txt` or `pdf`) — inferred from `-o` if omitted

Examples:

```bash
# list interfaces
myenv/Scripts/python.exe main.py -t 192.168.100.0/24 --list-ifaces

# automatic interface selection, 2 attempts
myenv/Scripts/python.exe main.py -t 192.168.100.0/24

# manual interface and longer scan
myenv/Scripts/python.exe main.py -t 192.168.100.0/24 -i "Ethernet" --retries 5 --timeout 3

# save to text
myenv/Scripts.python.exe main.py -t 192.168.100.0/24 -o results.txt

# save to PDF (requires reportlab installed in the active env)
myenv/Scripts/python.exe main.py -t 192.168.100.0/24 -o results.pdf
```

---

## Interface selection (short)

If you don't pass `-i`, the scanner prefers an interface with an IP in the target subnet; otherwise it falls back to a non-loopback interface with a valid MAC.

## Snapshot placeholders

Add terminal/output snapshots into `docs/snapshots/` and link them into this README. Example markdown to include:

```markdown
### Terminal run
![Terminal snapshot](https://github.com/salmanmallah/ARP-SCANNER-/blob/master/snapshots/snapshot_0.png)


### Output file
![Terminal snapshot](https://github.com/salmanmallah/ARP-SCANNER-/blob/master/snapshots/snapshot_1.png)

```

1. If you provide `-i`, the script will try to match either the raw NPF key (\\Device\\NPF_{...}) or a friendly name.
2. If a target network is given, it prefers an interface whose IPv4 address is in that subnet.
3. Otherwise it picks the first non-loopback, non-virtual interface with a valid MAC.

This avoids Scapy trying to use stale or loopback-only adapters and causing hard-to-read tracebacks.

---




## Why some devices may not appear

ARP scans only find devices that reply at Layer 2. If a device doesn't appear:

- It may be offline, asleep, or disconnected.
- It may be on another subnet/VLAN or client-isolated by the AP.
- A firewall or special device config may block ARP responses.

Tips:

- Check your router/AP's DHCP/ARP table for the device.
- Try a targeted ARP probe or ICMP ping from another machine on the network.
- Increase `--retries` and `--timeout`.

---

## License

MIT-style: use and modify freely.

- Install Npcap — WinPcap is deprecated.
- Run your shell as Administrator to send raw packets.
- If you see `Interface 'Microsoft KM-TEST Loopback Adapter' not found`, run `--list-ifaces` and pass `-i` with the correct NPF key or friendly name.

---

## .gitignore suggestion

Create a `.gitignore` to avoid committing the virtualenv and generated files (see included `.gitignore`). You can customize it if you want some outputs tracked.

---

## Contributing

PRs welcome. Small tests or a `--dry-run` mode would be useful additions.

---

## License

MIT-style: use and modify freely.

---

If you want a Hindi translation of this README (short or full), tell me and I'll add it below or in a separate `README.hi.md`.
