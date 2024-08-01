from scapy.all import sniff, wrpcap
import os

def packet_callback(packet):
    print("Packet captured:")
    print(packet.summary())

def main():
    # Ask for the network interface to sniff on
    interface = input("Enter the network interface (e.g., eth0, wlan0): ")

    # Ask for the filename to store the captured packets
    filename = input("Enter the filename to save the captured packets (e.g., capture.pcap): ")

    # Ensure the file has the .pcap extension
    if not filename.endswith(".pcap"):
        filename += ".pcap"

    # Inform the user that sniffing is starting
    print(f"Starting packet capture on interface {interface}. Press Ctrl+C to stop.")

    # Capture packets and store them in the file
    packets = sniff(iface=interface, prn=packet_callback)
    
    # Save the captured packets to the specified file
    wrpcap(filename, packets)
    print(f"Captured packets saved to {filename}")

if __name__ == "__main__":
    main()
