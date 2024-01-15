import sys
from scapy.all import srp, ARP, ICMP, IP, sniff
import argparse

def write_to_file(filename, data):
    with open(filename, "a") as file:
        file.write(data + "\n")

def active_discovery(host, output_file=None):
    print(f"Active Discovery on {host}")
    ans, _ = srp(IP(dst=host)/ICMP(), timeout=2, verbose=False)
    for sent, received in ans:
        result = f"Host Detected: {received.src}"
        print(result)
        if output_file:
            write_to_file(output_file, result)

def passive_discovery(target_ip, output_file=None):
    print("Passive Discovery (listening for ARP packets)")
    def arp_display(pkt):
        if pkt[ARP].op == 2:  # réponse ARP
            if target_ip == pkt[ARP].psrc:
                result = f"Host Detected: {pkt[ARP].hwsrc} at {pkt[ARP].psrc}"
                print(result)
                if output_file:
                    write_to_file(output_file, result)
    sniff(prn=arp_display, filter="arp", store=0, count=10)

def test_hosts(network, output_file=None):
    print(f"Testing hosts in {network}")
    ans, _ = srp(IP(dst=network)/ICMP(), timeout=2, verbose=False)
    for sent, received in ans:
        result = f"Host Detected: {received.src}"
        print(result)
        if output_file:
            write_to_file(output_file, result)

def main():
    parser = argparse.ArgumentParser(description="Host Discovery Tool")
    parser.add_argument("-a", "--active", help="Active discovery on a specific host")
    parser.add_argument("-p", "--passive", help="Passive discovery on a specific host")
    parser.add_argument("-t", "--test", help="Test presence of hosts in a network")
    parser.add_argument("-x", "--export", help="Export results to a file")

    args = parser.parse_args()

    output_file = args.export

    if args.active:
        active_discovery(args.active, output_file)
    elif args.passive:
        passive_discovery(args.passive, output_file)
    elif args.test:
        test_hosts(args.test, output_file)
    else:
        print("No valid option selected. Use -a, -p, or -t.")

if __name__ == "__main__":
    main()