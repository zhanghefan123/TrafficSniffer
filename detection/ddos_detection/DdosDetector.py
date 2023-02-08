from pyecharts.charts import Line
from detection.detector.PacketDetector import PacketDetector
import numpy as np
from pyecharts import options as opts
from pojo.Packets import Packets


class DdosDetector(PacketDetector):
    distanceList = []

    def __init__(self, packets):
        self.packets = packets

    # 实现逻辑判断
    def logistic(self):
        identifier_matrix = np.array([self.packets.urgent_bit,
                                      self.packets.acknowledgement_bit,
                                      self.packets.push_bit,
                                      self.packets.reset_bit,
                                      self.packets.synchronize_bit,
                                      self.packets.finish_bit]).T
        cov_matrix = np.cov(identifier_matrix, rowvar=False)
        Packets.sum_conv_matrix += cov_matrix
        mean_of_matrix = Packets.sum_conv_matrix / Packets.tcp_capture_round
        distance = self.__calculateDistance(cov_matrix, mean_of_matrix)
        DdosDetector.distanceList.append(round(distance, 3))
        return distance

    # 实现日志记录
    def logger(self, packet):
        pass

    def plot_line_distance_with_pyecharts(self):
        line = Line()
        print(self.distanceList)
        line.add_xaxis(range(len(DdosDetector.distanceList)))
        line.add_yaxis("距离", DdosDetector.distanceList)
        # 显示的时候保留两位小数
        line.set_series_opts(label_opts=opts.LabelOpts(is_show=True))
        line.render("distance.html")

    @classmethod
    def __calculateDistance(cls, first_matrix, second_matrix):
        # 每两个矩阵的点之间的距离的平方和开根号
        distance = np.sqrt(np.sum(np.square(first_matrix - second_matrix)))
        return distance
