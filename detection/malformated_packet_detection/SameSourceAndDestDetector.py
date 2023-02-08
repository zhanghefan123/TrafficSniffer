from scapy.layers.inet import IP

from detection.detector.PacketDetector import PacketDetector
from loguru import logger


class SameSourceAndDestDetector(PacketDetector):

    # 实现逻辑判断
    def logistic(self, packet):
        if packet.haslayer(IP):
            return packet[IP].src == packet[IP].dst
        else:
            return False

    # 实现日志记录
    def logger(self, packet):
        logger.warning("Same source and destination IP address detected: " + packet[IP].src + " " + packet[IP].dst)
