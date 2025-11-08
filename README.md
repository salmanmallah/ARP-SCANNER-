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

## Usage & options

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

## How interface selection works

1. If you provide `-i`, the script will try to match either the raw NPF key (\\Device\\NPF_{...}) or a friendly name.
2. If a target network is given, it prefers an interface whose IPv4 address is in that subnet.
3. Otherwise it picks the first non-loopback, non-virtual interface with a valid MAC.

This avoids Scapy trying to use stale or loopback-only adapters and causing hard-to-read tracebacks.

---

## Snapshot placeholders (add your terminal + output snapshots here)

You can add screenshots or output files later. Recommended folder: `docs/snapshots/`.

1. Create the folder in the repo:

```bash
mkdir -p docs/snapshots
```

2. Place your terminal snapshot (PNG) and output snapshot (PNG or the actual output PDF) inside `docs/snapshots/`.

3. Add the following markdown into this README where you'd like the snapshot to appear (example):

```markdown
### Terminal run (example)
![Terminal snapshot](docs/snapshots/terminal_snapshot.png)

### Output file (example)
[Download scan output PDF](docs/snapshots/scan_output.pdf)
or
![Output snapshot](docs/snapshots/output_snapshot.png)
```

When you're ready, commit the snapshots or keep them locally and remove them from tracking via `.gitignore` as desired.

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

## Troubleshooting (Windows)

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
