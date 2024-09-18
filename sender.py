import scapy.all as scapy
import sys
import math
import psutil

class ICMPTunneling:
    @staticmethod
    def send_icmp_packet(dst_ip, payload=""):
        packet = scapy.IP(dst=dst_ip)/scapy.ICMP(type=8)/payload
        reply = scapy.sr1(packet, timeout=2, verbose=False)
        return reply

    @staticmethod
    def initiate_session(dst_ip):
        print("Starting ICMP tunnel session...")
        ICMPTunneling.send_icmp_packet(dst_ip)

    @staticmethod
    def terminate_session(dst_ip):
        print("Ending ICMP tunnel session...")
        ICMPTunneling.send_icmp_packet(dst_ip)

    @staticmethod
    def split_payload(payload, mtu):
        """Split the payload into chunks that fit within the MTU."""
        max_payload_size = mtu - 28  # 20 bytes for IP header + 8 bytes for ICMP header
        return [payload[i:i + max_payload_size] for i in range(0, len(payload), max_payload_size)]

    @staticmethod
    def get_mtu():
        iface = scapy.conf.iface
        for nic, addrs in psutil.net_if_addrs().items():
            if nic == iface:
                mtu = psutil.net_if_stats()[nic].mtu
                return mtu
        return 1500  # Default MTU value if not found

    @staticmethod
    def command_icmp_tunnel(dst_ip):
        mtu = ICMPTunneling.get_mtu()
        while True:
            try:
                command = input("Enter the command to execute (or 'exit' to quit): ").strip()
                if command.lower() == 'exit':
                    print("Exiting...")
                    break

                # Split the command if it's larger than the MTU
                payload_chunks = ICMPTunneling.split_payload(command, mtu)

                for chunk in payload_chunks:
                    reply = ICMPTunneling.send_icmp_packet(dst_ip, chunk)

                    if reply and scapy.ICMP in reply and reply[scapy.ICMP].type == 0:
                        if scapy.Raw in reply:
                            print(f"Received reply:\n{reply[scapy.Raw].load.decode()}")
                        else:
                            print("No data received in the reply.")
                    else:
                        print("No reply or invalid reply received.")
            
            except KeyboardInterrupt:
                print("\nProcess interrupted by the user. Exiting...")
                break

def main():
    if len(sys.argv) < 2:
        print("Usage: python sender_script.py <target_ip>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    ICMPTunneling.initiate_session(target_ip)
    ICMPTunneling.command_icmp_tunnel(target_ip)
    ICMPTunneling.terminate_session(target_ip)

if __name__ == "__main__":
    main()
