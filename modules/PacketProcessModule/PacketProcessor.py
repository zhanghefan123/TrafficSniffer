from scapy.layers.inet import TCP, UDP, IP
import pandas as pd
from pojo.Packets import Packets
from const.ConstVariable import SINGLE_TIME_CAPTURE_PACKETS, DATA_STORAGE_PATH
from modules.CurrentTimeModule.CurrentTime import CurrentTime
import datetime


class PacketProcessor:
    pojo_packets = Packets()
    from_packet = 0
    to_packet = SINGLE_TIME_CAPTURE_PACKETS

    @classmethod
    def put_scapy_packet_into_pojo_packets(cls, scapy_packet):
        if scapy_packet.haslayer(IP):
            cls.pojo_packets.source_ip[Packets.packet_count] = scapy_packet[IP].src
            cls.pojo_packets.destination_ip[Packets.packet_count] = scapy_packet[IP].dst
            cls.pojo_packets.header_length[Packets.packet_count] = scapy_packet[IP].ihl
            cls.pojo_packets.total_length[Packets.packet_count] = scapy_packet[IP].len
            cls.pojo_packets.ttl[Packets.packet_count] = scapy_packet[IP].ttl
        if scapy_packet.haslayer(TCP):
            cls.pojo_packets.transport_protocol[Packets.packet_count] = "TCP"
            cls.pojo_packets.source_port[Packets.packet_count] = scapy_packet[TCP].sport
            cls.pojo_packets.destination_port[Packets.packet_count] = scapy_packet[TCP].dport
            cls.pojo_packets.urgent_bit[Packets.packet_count] = scapy_packet[TCP].flags.U
            cls.pojo_packets.acknowledgement_bit[Packets.packet_count] = scapy_packet[TCP].flags.A
            cls.pojo_packets.push_bit[Packets.packet_count] = scapy_packet[TCP].flags.P
            cls.pojo_packets.reset_bit[Packets.packet_count] = scapy_packet[TCP].flags.R
            cls.pojo_packets.synchronize_bit[Packets.packet_count] = scapy_packet[TCP].flags.S
            cls.pojo_packets.finish_bit[Packets.packet_count] = scapy_packet[TCP].flags.F
            Packets.tcp_packet_count += 1  # increase tcp packet count
            if scapy_packet[TCP].flags.U:
                Packets.urg_count += 1
            if scapy_packet[TCP].flags.A:
                Packets.ack_count += 1
            if scapy_packet[TCP].flags.P:
                Packets.psh_count += 1
            if scapy_packet[TCP].flags.R:
                Packets.rst_count += 1
            if scapy_packet[TCP].flags.S:
                Packets.syn_count += 1
            if scapy_packet[TCP].flags.F:
                Packets.fin_count += 1
        elif scapy_packet.haslayer(UDP):
            cls.pojo_packets.transport_protocol[Packets.packet_count] = "UDP"
            cls.pojo_packets.source_port[Packets.packet_count] = scapy_packet[UDP].sport
            cls.pojo_packets.destination_port[Packets.packet_count] = scapy_packet[UDP].dport
            Packets.udp_packet_count += 1  # increase udp packet count
        Packets.packet_count += 1  # increase packet count

    @classmethod
    def process(cls, scapy_packet):
        """
        process the packet
        :param scapy_packet: scapy sniff packet
        :return:
        """
        cls.put_scapy_packet_into_pojo_packets(scapy_packet)
        if Packets.packet_count == SINGLE_TIME_CAPTURE_PACKETS:
            df_packets = pd.DataFrame(cls.pojo_packets.__dict__)
            cls.write_to_csv(df_packets, DATA_STORAGE_PATH,
                             f"{cls.from_packet} packet~{cls.to_packet} packet-startTime-"
                             f"{CurrentTime.get_current_time()}.csv")
            df_statistis = pd.DataFrame(Packets.get_statistics(), index=[0])
            cls.write_to_csv(df_statistis, DATA_STORAGE_PATH,
                             f"{cls.from_packet} packet~{cls.to_packet} packet-statistics-startTime-"
                             f"{CurrentTime.get_current_time()}.csv")
            cls.pojo_packets.clear()
            cls.from_packet = cls.to_packet
            cls.to_packet += SINGLE_TIME_CAPTURE_PACKETS

    @classmethod
    def write_to_csv(cls, df, csv_dir_path, csv_file_name):
        """
        write the dataframe to csv
        :param df:  the dataframe
        :param csv_dir_path:  the csv file dir path
        :param csv_file_name:  the csv file name
        :return:
        """
        df.to_csv(csv_dir_path + csv_file_name, index=False)
