import numpy as np
import pandas as pd
from const.ConstVariable import TCP_PROTOCOL_NUMBER, UDP_PROTOCOL_NUMBER, SINGLE_TIME_CAPTURE_PACKETS


# 一次进行数据包的抓取所获取的数据结构
class Packets:
    # here are some statistics result 这些一定要是静态字段从而可以便于进行区分
    # --------------------------------------------------------------------------------------
    packet_count = 0
    udp_packet_count = 0
    tcp_packet_count = 0
    urg_count = 0
    ack_count = 0
    psh_count = 0
    rst_count = 0
    syn_count = 0
    fin_count = 0
    # --------------------------------------------------------------------------------------
    # 用来存储conv matrix 的总和
    sum_conv_matrix = np.zeros((6, 6), dtype=np.float32)
    # 用来存储抓取了多少轮
    capture_round = 0
    tcp_capture_round = 0

    def __init__(self):
        # network layer field
        # --------------------------------------------------------------------------------------
        self.transport_protocol = []
        self.source_ip = []  # source ip
        self.destination_ip = []  # destination ip
        self.header_length = []  # header length
        self.total_length = []  # total length
        self.ttl = []  # ttl
        # --------------------------------------------------------------------------------------

        # transport layer field
        # --------------------------------------------------------------------------------------
        self.source_port = []
        self.destination_port = []
        # --------------------------------------------------------------------------------------

        # six transport layer option field
        # --------------------------------------------------------------------------------------
        self.urgent_bit = []
        self.acknowledgement_bit = []
        self.push_bit = []
        self.reset_bit = []
        self.synchronize_bit = []
        self.finish_bit = []
        # --------------------------------------------------------------------------------------

    @classmethod
    def get_statistics(cls):
        """
        get the statistics result
        :return: a dict
        """
        return {
            "packet_count": cls.packet_count,
            "udp_packet_count": cls.udp_packet_count,
            "tcp_packet_count": cls.tcp_packet_count,
            "urg_count": cls.urg_count,
            "ack_count": cls.ack_count,
            "psh_count": cls.psh_count,
            "rst_count": cls.rst_count,
            "syn_count": cls.syn_count,
            "fin_count": cls.fin_count
        }

    def clear(self):
        """
        clear all the packets 清空所有的数据包
        :return: None
        """
        self.transport_protocol.clear()
        self.source_ip.clear()  # source ip
        self.destination_ip.clear()  # destination ip
        self.header_length.clear()  # header length
        self.total_length.clear()  # total length
        self.ttl.clear()  # ttl

        self.source_port.clear()
        self.destination_port.clear()

        self.urgent_bit.clear()
        self.acknowledgement_bit.clear()
        self.push_bit.clear()
        self.reset_bit.clear()
        self.synchronize_bit.clear()
        self.finish_bit.clear()

        Packets.packet_count = 0
        Packets.udp_packet_count = 0
        Packets.tcp_packet_count = 0
        Packets.urg_count = 0
        Packets.ack_count = 0
        Packets.psh_count = 0
        Packets.rst_count = 0
        Packets.syn_count = 0
        Packets.fin_count = 0
