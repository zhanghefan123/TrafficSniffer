from attack.land_attack import LandAttack
from const.ConstVariable import TOTAL_CAPTURE_PACKETS
from modules.SniffModule.Sniffer import Sniffer
from modules.PacketProcessModule.PacketProcessor import PacketProcessor
import threading

if __name__ == "__main__":
    # 创建一个processor对象
    packetProcessor = PacketProcessor()
    # 这里进行了一个测试
    sniffer = Sniffer(interface_name="en0", packet_count=TOTAL_CAPTURE_PACKETS, callback=packetProcessor.process)
    # 注意这里我们是开启了一个抓包的线程
    sniffer.start_sniff()
    # 这里我们进行包的发送的线程的开启
    landAttack = LandAttack("172.16.0.1", "172.16.0.1", 10, "en0")
    landAttack.start()
