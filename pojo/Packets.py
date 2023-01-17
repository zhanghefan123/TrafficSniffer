import numpy as np
import pandas as pd
from const.ConstVariable import TCP_PROTOCOL_NUMBER, UDP_PROTOCOL_NUMBER, SINGLE_TIME_CAPTURE_PACKETS


class Packets:

    # here are some statistcs result
    packet_count = 0
    udp_packet_count = 0
    tcp_packet_count = 0
    urg_count = 0
    ack_count = 0
    psh_count = 0
    rst_count = 0
    syn_count = 0
    fin_count = 0

    def __init__(self):
        # network layer field
        # -----------------------------------------
        self.transport_protocol = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=object)
        self.source_ip = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=object)  # source ip
        self.destination_ip = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=object)   # destination ip
        self.header_length = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int32)  # header length
        self.total_length = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int32)  # total length
        self.ttl = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int16)  # ttl
        # -----------------------------------------

        # transport layer field
        # -----------------------------------------
        self.source_port = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)
        self.destination_port = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)
        # -----------------------------------------

        # six transport layer option field
        # -----------------------------------------
        self.urgent_bit = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)   # URG
        self.acknowledgement_bit = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)   # ACK
        self.push_bit = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)   # PSH
        self.reset_bit = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)   # RST
        self.synchronize_bit = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)   # SYN
        self.finish_bit = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)   # FIN
        # -----------------------------------------

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
        clear all the packets
        :return: None
        """
        self.transport_protocol = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=object)
        self.source_ip = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=object)  # source ip
        self.destination_ip = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=object)  # destination ip
        self.header_length = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int32)  # header length
        self.total_length = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int32)  # total length
        self.ttl = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int16)  # ttl

        self.source_port = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)
        self.destination_port = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)
        self.urgent_bit = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)  # URG
        self.acknowledgement_bit = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)  # ACK
        self.push_bit = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)  # PSH
        self.reset_bit = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)  # RST
        self.synchronize_bit = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)  # SYN
        self.finish_bit = np.empty(SINGLE_TIME_CAPTURE_PACKETS, dtype=np.int8)  # FIN
        Packets.packet_count = 0
        Packets.udp_packet_count = 0
        Packets.tcp_packet_count = 0
        Packets.urg_count = 0
        Packets.ack_count = 0
        Packets.psh_count = 0
        Packets.rst_count = 0
        Packets.syn_count = 0
        Packets.fin_count = 0

