class PacketDetector:
    # 单一检测器的定义
    # 用于检测单一的数据包
    def logistic(self, packet):
        # 进行检测逻辑的判断
        return NotImplementedError()

    # 当有恶意数据包时，进行日志记录
    def logger(self, packet):
        # 进行日志记录
        return NotImplementedError()

    # 这个方法不用进行实现
    def detect(self, packet) -> bool:
        # 进行检测逻辑的判断
        # 如果不是恶意数据包
        if not self.logistic(packet):
            return False
        else:
            # 进行日志记录
            self.logger(packet)
            # 返回检测结果
            return True
