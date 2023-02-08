class DetectorList:
    def __init__(self):
        # 顺序检测的detector的列表
        self._detectors = []

    # 添加一个detector
    def add_detector(self, detector):
        self._detectors.append(detector)

    # 检测一个packet
    def detect(self, packet):
        for detector in self._detectors:
            detector.detect(packet)
