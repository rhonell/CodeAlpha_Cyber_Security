import socket
import struct

def sniff():
    # Create a raw socket and bind it to the public interface
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("Listening for packets...")
    while True:
        # Receive raw packet data
        raw_data, addr = sniffer.recvfrom(65536)
        
        # Extract Ethernet header
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        
        print("\nEthernet Frame:")
        print(f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

# Function to parse Ethernet frames
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:]

# Convert raw MAC address to readable format
def get_mac(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))

if __name__ == "__main__":
    sniff()
