from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime
import ipaddress  # Import ipaddress module to validate IP address

# Function to handle each packet
def handle_packet(packet, target_ip, protocol_filter):
    if packet.haslayer(IP):
        # Extract source and destination IP addresses and protocol number
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol_number = packet[IP].proto
        
        # Map protocol number to its human-readable name
        protocol_name = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }.get(protocol_number, f"Other ({protocol_number})")

        # Check if packet is destined for the specified IP and matches the protocol filter
        if dst_ip == target_ip and (protocol_name == protocol_filter or protocol_filter == "Any"):
            print(f"\nPacket captured at {datetime.datetime.now().strftime('%H:%M:%S')}:")
            print(f"From IP: {src_ip} to IP: {dst_ip} | Protocol: {protocol_name}")

            # Show additional details if payload is available
            if packet.haslayer(TCP) or packet.haslayer(UDP):
                try:
                    payload = bytes(packet[TCP].payload if packet.haslayer(TCP) else packet[UDP].payload)
                    if payload:
                        print(f"  Payload (first 40 bytes): {payload[:40]}")
                        print(f"  Total Payload Length: {len(payload)} bytes")
                except Exception as e:
                    print("  (Oops! Something went wrong while reading the payload.)")

            # Additional info for TCP or UDP protocols: Ports
            if protocol_name == "TCP" and packet.haslayer(TCP):
                print(f"  TCP Source Port: {packet[TCP].sport} | TCP Destination Port: {packet[TCP].dport}")
            elif protocol_name == "UDP" and packet.haslayer(UDP):
                print(f"  UDP Source Port: {packet[UDP].sport} | UDP Destination Port: {packet[UDP].dport}")

            print("-" * 60)

print("=" * 80)

# Get user input for target IP and protocol filter with error handling
target_ip = input("Please enter the target IP address you'd like to monitor (e.g., 192.168.1.1): ")

# Validate if the IP address is valid
while not target_ip:
    print("Hmm, you didn’t type anything. Could you please enter an IP address?")
    target_ip = input("Please enter the target IP address you'd like to monitor (e.g., 192.168.1.1): ")

# Check if the input IP address is valid
while True:
    try:
        ipaddress.ip_address(target_ip)  # Validate the IP address format
        break  # Exit the loop if IP is valid
    except ValueError:
        print(f"Oops! '{target_ip}' is not a valid IP address. Please type a valid one (e.g., 192.168.1.1).")
        target_ip = input("Please enter the target IP address you'd like to monitor (e.g., 192.168.1.1): ")

protocol_filter = input("Which protocol would you like to monitor? (TCP/UDP/ICMP/Any): ").upper()
while protocol_filter not in ["TCP", "UDP", "ICMP", "ANY"]:
    print("Oops! That doesn’t seem like a valid protocol. Please choose from: TCP, UDP, ICMP, or Any.")
    protocol_filter = input("Which protocol would you like to monitor? (TCP/UDP/ICMP/Any): ").upper()

# Offering some suggested packet capture options
print("\nHere are some suggestions for the number of packets to capture:")
print("1. 100 packets (Quick snapshot of traffic)")
print("2. 500 packets (Moderate traffic analysis)")
print("3. 1000 packets (In-depth traffic analysis)")
print("4. Or, type your own number if you prefer")

# Ask if the user wants to limit the number of packets
capture_limit = input("Would you like to limit the number of packets? Type 'yes' or 'no': ").lower()
while capture_limit not in ['yes', 'no']:
    print("Hmm, I need a simple 'yes' or 'no' answer. Please try again.")
    capture_limit = input("Would you like to limit the number of packets? Type 'yes' or 'no': ").lower()

num_packets = 0

if capture_limit == 'yes':
    choice = input("Choose from the suggestions (100, 500, 1000) or enter your own number: ")
    while not choice.isdigit() or int(choice) <= 0:
        print("Oops! That’s not a valid number. Please type a number greater than 0.")
        choice = input("Choose from the suggestions (100, 500, 1000) or enter your own number: ")
    num_packets = int(choice)

# Start sniffing packets
print("\nAlright, I’m starting to sniff packets now... (Press Ctrl + C if you want to stop)")

# Use `count` to limit the number of packets if the user specified a limit
if num_packets > 0:
    sniff(prn=lambda packet: handle_packet(packet, target_ip, protocol_filter), store=False, count=num_packets)
else:
    sniff(prn=lambda packet: handle_packet(packet, target_ip, protocol_filter), store=False)
