import sys
import argparse

try:
    import scapy.all as scapy
except Exception as e:
    print("\n[-] Missing dependency: scapy could not be imported.")
    print("    * If you use the included virtualenv, run: \n      myenv\\Scripts\\activate (Windows CMD) or source myenv/bin/activate (bash)")
    print("    * Or install scapy in your environment: pip install scapy")
    print(f"    * Import error: {e}")
    sys.exit(1)


import ipaddress
import time

# PDF support imports: try to import at top but tolerate missing package so the
# script won't crash when reportlab is not installed (still keeping imports
# at top-level per preference).
HAS_REPORTLAB = False
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    HAS_REPORTLAB = True
except Exception:
    # reportlab not available; save_results() will fall back to TXT output
    letter = None
    canvas = None


def choose_interface(preferred_iface=None, target=None):
    """Choose a network interface to use with Scapy.

    If the user provided an interface name, validate it. Otherwise pick the
    first reasonable non-loopback interface. Returns the interface name or
    None if no suitable interface is found.
    """
    try:
        available = scapy.get_if_list()
    except Exception:
        available = []

    # If user provided an iface, try to resolve it (allow either NPF key or friendly name)
    if preferred_iface:
        # exact match for NPF key
        if preferred_iface in available:
            return preferred_iface
        # try case-insensitive match on NPF key
        for i in available:
            if i.lower() == preferred_iface.lower():
                return i
        # try matching friendly name via scapy.ifaces mapping
        try:
            for k, v in scapy.ifaces.data.items():
                if v and getattr(v, 'name', None) and v.name.lower() == preferred_iface.lower():
                    return k
        except Exception:
            pass
        return None

    # If a target network was provided, prefer an interface whose IP falls
    # in the same network (most reliable selection).
    if target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            for iface in available:
                try:
                    # try to get the human-friendly iface name
                    friendly = scapy.ifaces.data.get(iface).name if scapy.ifaces.data.get(iface) else iface
                except Exception:
                    friendly = iface
                # skip obvious virtual or loopback device keys
                if friendly and any(k in friendly.lower() for k in ("loopback", "loop", "virtual", "vmware", "tunnel", "pseudo", "km-test")):
                    continue
                try:
                    addr = scapy.get_if_addr(iface)
                    if addr and addr != '0.0.0.0':
                        if ipaddress.ip_address(addr) in net:
                            return iface
                except Exception:
                    continue
        except Exception:
            # if parsing network failed, fall back to heuristics below
            pass

    # Heuristics: prefer interfaces which don't look like loopback or test adapters
    bad_keywords = ("loopback", "loop", "virtual", "tunnel", "pseudo", "km-test")
    for iface in available:
        try:
            friendly = scapy.ifaces.data.get(iface).name if scapy.ifaces.data.get(iface) else iface
        except Exception:
            friendly = iface
        lname = friendly.lower() if friendly else iface.lower()
        if any(k in lname for k in bad_keywords) or 'vmware' in lname:
            continue
        try:
            mac = scapy.get_if_hwaddr(iface)
        except Exception:
            mac = None
        # skip interfaces without a real MAC
        if mac and mac != "00:00:00:00:00:00":
            return iface

    # fallback: if nothing matched, return the first non-empty interface
    for iface in available:
        if iface:
            return iface

    return None

def get_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="Simple ARP Network Scanner")
    parser.add_argument("-t", "--target", dest="target", 
                        required=True, help="Target IP address or IP range to scan (e.g., 192.168.1.1/24)")
    parser.add_argument("-i", "--iface", dest="iface",
                        required=False, help="(Optional) Interface name to use for sending packets")
    parser.add_argument("--list-ifaces", dest="list_ifaces", action='store_true',
                        required=False, help="List detected interfaces and exit")
    parser.add_argument("--timeout", dest="timeout", type=float, default=2.0,
                        required=False, help="Timeout (seconds) to wait for ARP replies per attempt")
    parser.add_argument("--retries", dest="retries", type=int, default=2,
                        required=False, help="Number of ARP attempts to perform (aggregates unique replies)")
    parser.add_argument("-o", "--output", dest="output", required=False,
                        help="Optional output file name to save results (extension .txt or .pdf will be used to select format)")
    parser.add_argument("--format", dest="out_format", choices=("txt","pdf"), required=False,
                        help="Optional explicit output format (txt or pdf). If omitted, inferred from -o extension or defaults to txt")
    args = parser.parse_args()
    return args

def scan(ip):
    """
    Scans the given IP range using ARP requests.

    Args:
        ip (str): The IP address or IP range to scan (e.g., "192.168.1.1/24").

    Returns:
        list: A list of dictionaries, where each dictionary contains
              the 'ip' and 'mac' address of a discovered client.
    """
    # Determine the source MAC for the chosen interface and build packets
    # Create an Ethernet broadcast packet
    # hwdst (MACField) = Destination MAC address ("ff:ff:ff:ff:ff:ff" is broadcast)
    # Set the source MAC explicitly from the chosen interface to avoid
    # Scapy attempting to auto-resolve an invalid/old interface name.
    try:
        src_mac = scapy.get_if_hwaddr(scapy.conf.iface)
    except Exception:
        src_mac = None

    if src_mac:
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac)
    else:
        # If we couldn't determine a source MAC, fail early with a clear message
        print("\n[-] Could not determine source MAC for interface:", scapy.conf.iface)
        print("    Make sure the interface is up and has a valid MAC address.")
        return []

    # Create an ARP request packet
    # pdst (IPAddrField) = Destination IP address (who to ask)
    # Set hwsrc explicitly so Scapy doesn't attempt to resolve a wrong
    # interface name when building the packet.
    arp_request = scapy.ARP(pdst=ip, hwsrc=src_mac)
    # Combine the Ethernet frame and ARP request
    arp_request_broadcast = broadcast / arp_request
    
    # Send the packet and receive responses
    # srp = Send and Receive Packet (at layer 2)
    # timeout=1 means wait 1 second for responses
    # verbose=False cleans up the output
    # Send the ARP broadcast and collect responses over one or more attempts.
    # We'll perform multiple attempts to improve chance of discovering devices
    # that might be temporarily unreachable (WiFi power save, host firewall, etc.).
    clients = {}
    return_list = []
    # read retries/timeout from scapy.conf._temp if we stored them earlier, else use defaults
    retries = getattr(scapy.conf, 'user_retries', 2)
    timeout = getattr(scapy.conf, 'user_timeout', 2.0)
    for attempt in range(max(1, int(retries))):
        try:
            answered = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]
        except Exception as e:
            print("ERROR: Failed to send/receive packets. Are you running as Administrator and is Npcap installed?")
            print("    Scapy error:", e)
            break

        for element in answered:
            resp = element[1]
            ipaddr = getattr(resp, 'psrc', None)
            macaddr = getattr(resp, 'hwsrc', None)
            if ipaddr and macaddr:
                clients[ipaddr] = macaddr

        # small pause between attempts to avoid flooding
        if attempt + 1 < retries:
            time.sleep(0.2)

    # Build return list ordered by IP
    for ipaddr in sorted(clients, key=lambda s: tuple(int(x) for x in s.split('.'))):
        return_list.append({"ip": ipaddr, "mac": clients[ipaddr]})

    return return_list
    
    clients_list = []
    for element in answered_list:
        # element[1] is the response
        # psrc = Source IP (the IP of the responding device)
        # hwsrc = Source MAC (the MAC of the responding device)
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    
    return clients_list

def print_result(results_list):
    """Prints the scan results in a clean table."""
    print("----------------------------------------------------")
    print("IP Address\t\tMAC Address")
    print("----------------------------------------------------")
    for client in results_list:
        print(f"{client['ip']}\t\t{client['mac']}")


def save_results(results_list, filename, fmt="txt"):
    """Save results to filename in either txt or pdf format.

    If PDF support (reportlab) is not available, the function will fall back
    to writing a TXT file and inform the user.
    """
    if not results_list:
        print(f"[i] No results to save to {filename}")
        return

    fmt = (fmt or "txt").lower()
    if fmt not in ("txt", "pdf"):
        fmt = "txt"

    if fmt == "txt":
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("IP Address\tMAC Address\n")
                f.write("------------------------------------------\n")
                for r in results_list:
                    f.write(f"{r['ip']}\t{r['mac']}\n")
            print(f"[+] Results written to {filename}")
        except Exception as e:
            print(f"[-] Failed to write TXT output: {e}")
        return

    # PDF output: use top-level reportlab import if available, else fallback to TXT
    if not HAS_REPORTLAB:
        print("[-] reportlab not installed; falling back to TXT output. To enable PDF output, install reportlab: pip install reportlab")
        txt_name = filename if filename.lower().endswith('.txt') else filename + '.txt'
        try:
            with open(txt_name, "w", encoding="utf-8") as f:
                f.write("IP Address\tMAC Address\n")
                f.write("------------------------------------------\n")
                for r in results_list:
                    f.write(f"{r['ip']}\t{r['mac']}\n")
            print(f"[+] Results written to {txt_name}")
        except Exception as e:
            print(f"[-] Failed to write fallback TXT output: {e}")
        return

    # Generate PDF using reportlab imported at module top
    try:
        pdf_name = filename if filename.lower().endswith('.pdf') else filename + '.pdf'
        c = canvas.Canvas(pdf_name, pagesize=letter)
        width, height = letter
        x = 40
        y = height - 40
        c.setFont('Helvetica-Bold', 12)
        c.drawString(x, y, 'ARP Scan Results')
        y -= 20
        c.setFont('Helvetica-Bold', 10)
        c.drawString(x, y, 'IP Address')
        c.drawString(x + 200, y, 'MAC Address')
        y -= 12
        c.line(x, y, width - 40, y)
        y -= 16
        c.setFont('Helvetica', 10)
        for r in results_list:
            if y < 60:
                c.showPage()
                y = height - 40
                c.setFont('Helvetica', 10)
            c.drawString(x, y, r['ip'])
            c.drawString(x + 200, y, r['mac'])
            y -= 14
        c.save()
        print(f"[+] PDF written to {pdf_name}")
    except Exception as e:
        print(f"[-] Failed to write PDF: {e}")

if __name__ == "__main__":
    try:
        args = get_arguments()

        if args.list_ifaces:
            # Print a friendly mapping of NPF keys -> friendly name and MAC
            print("Detected interfaces:")
            for k, v in scapy.ifaces.data.items():
                try:
                    name = getattr(v, 'name', None) or k
                    mac = getattr(v, 'mac', None) or scapy.get_if_hwaddr(k)
                except Exception:
                    name = k
                    mac = 'unknown'
                print(f"{k} -> {name} (MAC: {mac})")
            raise SystemExit(0)

        # Pick and set the interface before building/sending packets so Scapy
        # doesn't attempt to resolve a wrong default (which can raise the
        # "Interface '...not found'" ValueError on Windows).
        chosen = choose_interface(args.iface, args.target)
        if chosen is None:
            print("\n[-] No suitable network interface found.")
            print("    * Make sure Npcap is installed (WinPcap is deprecated) and run as Administrator.")
            print("    * You can also specify an interface with -i e.g. -i \"Ethernet 2\"")
            raise SystemExit(1)

        scapy.conf.iface = chosen
        # reduce Scapy verbosity globally
        scapy.conf.verb = 0
        # store user-specified timeout/retries on conf so scan() can read them
        scapy.conf.user_timeout = float(args.timeout)
        scapy.conf.user_retries = int(args.retries)
        print(f"[i] Using interface: {chosen}")
        print(f"[i] Timeout: {scapy.conf.user_timeout}s, Retries: {scapy.conf.user_retries}")
        scan_result = scan(args.target)

        if not scan_result:
            print(f"[-] No devices found on {args.target}")
        else:
            print(f"[+] Devices found on {args.target}:\n")
            print_result(scan_result)

        # If output filename provided, save results in chosen format
        if args.output:
            out_fmt = args.out_format if args.out_format else ("pdf" if args.output.lower().endswith('.pdf') else "txt")
            save_results(scan_result, args.output, out_fmt)

    except KeyboardInterrupt:
        print("\n[-] Scan stopped by user.")
    except PermissionError:
        print("\n[-] Error: You need to run this script with root/administrator privileges.")
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {e}")