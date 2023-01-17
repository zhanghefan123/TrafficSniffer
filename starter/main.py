from const.ConstVariable import TOTAL_CAPTURE_PACKETS
from modules.SniffModule.Sniffer import Sniffer
from modules.PacketProcessModule.PacketProcessor import PacketProcessor

if __name__ == "__main__":
    sniffer = Sniffer(interface_name="lo", packet_count=TOTAL_CAPTURE_PACKETS, callback=PacketProcessor.process)
    sniffer.start_sniff()
