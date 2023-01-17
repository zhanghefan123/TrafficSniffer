from scapy.all import *


class Sniffer:
    def __init__(self, interface_name, packet_count, callback):
        self.interface_name = interface_name
        self.packet_count = packet_count
        self.callback = callback

    def start_sniff(self):
        sniff(iface=self.interface_name,
              prn=self.callback,
              count=self.packet_count)
