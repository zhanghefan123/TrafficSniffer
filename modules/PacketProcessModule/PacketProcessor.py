from scapy.layers.inet import TCP, UDP, IP
from detection.ddos_detection.DdosDetector import DdosDetector
from detection.detector.PacketDetectorList import DetectorList
from detection.malformated_packet_detection.SameSourceAndDestDetector import SameSourceAndDestDetector
from pojo.Packets import Packets
from const.ConstVariable import SINGLE_TIME_CAPTURE_PACKETS, DATA_STORAGE_PATH, TOTAL_CAPTURE_PACKETS, \
    TCP_SINGLE_TIME_CAPTURE_PACKETS
from loguru import logger


# 用于处理packets的类
class PacketProcessor:

    # 实例化方法
    def __init__(self):
        self.currentPacketCount = 0  # 当前已经处理的包的数量
        self.detectorList = DetectorList()  # create a detector list
        self.detectorList.add_detector(SameSourceAndDestDetector())  # add a detector
        self.pojo_packets = Packets()  # create a pojo packet
        self.from_packet = 0  # the first packet to be processed
        self.to_packet = SINGLE_TIME_CAPTURE_PACKETS  # the last packet to be processed
        self.ddos_detector = ""  # ddos detector

    def put_scapy_packet_into_pojo_packets(self, scapy_packet):
        if scapy_packet.haslayer(IP):
            self.pojo_packets.source_ip.append(scapy_packet[IP].src)
            self.pojo_packets.destination_ip.append(scapy_packet[IP].dst)
            self.pojo_packets.header_length.append(scapy_packet[IP].ihl)
            self.pojo_packets.total_length.append(scapy_packet[IP].len)
            self.pojo_packets.ttl.append(scapy_packet[IP].ttl)
        if scapy_packet.haslayer(TCP):
            self.pojo_packets.transport_protocol.append("TCP")
            self.pojo_packets.source_port.append(scapy_packet[TCP].sport)
            self.pojo_packets.destination_port.append(scapy_packet[TCP].dport)
            # 6 个标志位，使用 6 个numpy 数组来进行声明
            self.pojo_packets.urgent_bit.append(int(scapy_packet[TCP].flags.U))
            self.pojo_packets.acknowledgement_bit.append(int(scapy_packet[TCP].flags.A))
            self.pojo_packets.push_bit.append(int(scapy_packet[TCP].flags.P))
            self.pojo_packets.reset_bit.append(int(scapy_packet[TCP].flags.R))
            self.pojo_packets.synchronize_bit.append(int(scapy_packet[TCP].flags.S))
            self.pojo_packets.finish_bit.append(int(scapy_packet[TCP].flags.F))

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
            # self.pojo_packets.transport_protocol[Packets.packet_count] = "UDP"
            # self.pojo_packets.source_port[Packets.packet_count] = scapy_packet[UDP].sport
            # self.pojo_packets.destination_port[Packets.packet_count] = scapy_packet[UDP].dport
            self.pojo_packets.transport_protocol.append("UDP")
            self.pojo_packets.source_port.append(scapy_packet[UDP].sport)
            self.pojo_packets.destination_port.append(scapy_packet[UDP].dport)
            Packets.udp_packet_count += 1  # increase udp packet count
        Packets.packet_count += 1  # increase packet count
        self.currentPacketCount += 1  # increase current packet count

    def process(self, scapy_packet):
        """
        process the packet
        :param scapy_packet: scapy sniff packet
        :return:
        """
        # 放到存储一批量数据包的pojo中
        self.put_scapy_packet_into_pojo_packets(scapy_packet)
        # 在这里进行恶意流量监测
        self.detectorList.detect(scapy_packet)
        # 创建ddos检测器
        self.ddos_detector = DdosDetector(self.pojo_packets)
        # 如果到了数量则停止
        if Packets.packet_count == SINGLE_TIME_CAPTURE_PACKETS:
            # 下面这些代码进行的是将数据包的信息写入csv文件中
            # 现在由于不是numpy 而是 list 所以需要进行更改
            # 没有直接的to_csv方法
            # ------------------------------------------------------------------------------------------
            # df_packets = pd.DataFrame(self.pojo_packets.__dict__)
            # self.write_to_csv(df_packets, DATA_STORAGE_PATH,
            #                  f"{self.from_packet} packet~{self.to_packet} packet-startTime-"
            #                  f"{CurrentTime.get_current_time()}.csv")
            # df_statistics = pd.DataFrame(Packets.get_statistics(), index=[0])
            # self.write_to_csv(df_statistics, DATA_STORAGE_PATH,
            #                  f"{self.from_packet} packet~{self.to_packet} packet-statistics-startTime-"
            #                  f"{CurrentTime.get_current_time()}.csv")
            # ------------------------------------------------------------------------------------------
            # 在这里也进行检测
            Packets.capture_round += 1
            self.pojo_packets.clear()
            self.from_packet = self.to_packet
            self.to_packet += SINGLE_TIME_CAPTURE_PACKETS
            logger.info(f"current packet count: {self.currentPacketCount}")
        # 如果到了一轮tcp抓包的数量就停止
        if Packets.tcp_packet_count == TCP_SINGLE_TIME_CAPTURE_PACKETS:
            Packets.tcp_capture_round += 1
            distance = self.ddos_detector.logistic()
            print(distance)
        # 如果到了总的数量就进行停止
        if self.currentPacketCount == TOTAL_CAPTURE_PACKETS:
            self.ddos_detector.plot_line_distance_with_pyecharts()

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