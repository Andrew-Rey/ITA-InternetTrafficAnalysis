import numpy as np
import pandas as pds
import matplotlib.pyplot as plt

from DeviceMap import device_map


class Samples(object):


    class RttDistribution(object):
        def __init__(self, timeout: int=None, step: int=None, prob: list=None) -> None:
            self.timeout = timeout
            self.step = step
            self.prob = prob
        
        def set(self, timeout: int, step: int, prob: list):
            self.timeout = timeout
            self.step = step
            self.prob = prob


    def __init__(self, read_file_path: str=None) -> None:
        """
        read rtt data and fit the distributions, generate data
        """
        self.__read_file_path_ = read_file_path
        self.__rtt_ = dict()
        self.__sample_model_ = dict()  # categories -> RttDistribution(timeout, step, prob)
        self.__count_ = 0
        self.__device_names_ = list()
        self.__class_indices_ = list()
        self.__average_rtt_ = list()
        self.__standar_rtt_ = list()

        # read from file, init device name list and count
        rtt_df = pds.read_csv(filepath_or_buffer=self.__read_file_path_, header=None, encoding="utf-8").fillna(0)
        self.__device_names_ = rtt_df.loc[:, 0].to_list()
        self.__count_ = len(self.__device_names_)

        # construct the map relations between device name and rtt data
        rtt_data_ = rtt_df.loc[:, 1:].to_numpy()
        for idx in range(len(self.__device_names_)):
            self.__rtt_[self.__device_names_[idx]] = rtt_data_[idx]

        # calculate average and standard
        self.__average_rtt_ = np.average(rtt_data_, axis=1)
        self.__standar_rtt_ = np.std(rtt_data_, axis=1)

        # construct the map between categories and models
        for _, value in device_map.items():
            self.__class_indices_.append(value["class"])
            if value["class"] not in self.__sample_model_ and value["class"] != -1:
                self.__sample_model_[value["class"]] = {
                    "distribution": self.RttDistribution(),
                    "device_names": list()
                }
        for _, value in device_map.items():
            self.__sample_model_[value["class"]]["device_names"].append(value["value"])
        # print(self.__sample_model_.items())


    def load(self):
        return self.__rtt_
    
    def fit(self, timeout: int=120, bin_width: int=10):
        """
        :param device_names_list: 同一类设备名字列表
        """
        for cls in self.__class_indices_:
            cls_rtt = list()
            cls_scalar = len(self.__sample_model_[cls]["device_names"])
            dnl = self.__sample_model_[cls]["device_names"]
            for dn in dnl:
                drtt = self.__rtt_[dn]                
                for item in drtt:
                    if 0 < item < timeout:
                        cls_rtt.append(item)
            cls_freq = pds.cut(cls_rtt, bins=[x for x in np.arange(0, timeout + 0.1, bin_width)])
            cls_freq = cls_freq.value_counts().values
            cls_freq = cls_freq / cls_scalar
            cls_prob = np.array([p / np.sum(cls_freq) for p in cls_freq])
            self.__sample_model_[cls]["distribution"].set(timeout, bin_width, cls_prob)
            print(self.__sample_model_[cls]["distribution"].prob)
        
    def sample(self, cls_idx: int=0, size: int=10):
        """
        根据分布随机抽取区间编号
        再在区间内进行随机抽样
        """
        model = self.__sample_model_[cls_idx]["distribution"]
        # print(np.arange(0, model.timeout + 0.1, model.step))
        # print(model.prob.size)
        left_pt = np.arange(0, model.timeout + 0.1, model.step)
        intervals = list()
        for l in range(0, len(left_pt) - 1):
            intervals.append([left_pt[l], left_pt[l + 1]])
        itvl_idx = np.linspace(0, len(left_pt) - 2, num=len(left_pt) - 1, endpoint=True)
        sampled_itvl = np.random.choice(itvl_idx, p=model.prob, size=size, replace=True)
        sampled = list()
        for idx in sampled_itvl:
            idx = int(idx)
            sampled.append(np.random.uniform(low=intervals[idx][0], high=intervals[idx][1]))
        return sampled

    def drawCategory(self, cls_idx: int=0, timeout: int=120, bins: int=120, figure_size: tuple=(6,4.5)):
        device_set = self.__sample_model_[cls_idx]["device_names"]
        cls_rtt = list()
        cls_all_rtt = list()
        for dn in device_set:
            cls_all_rtt.extend(self.__rtt_[dn])
        for item in cls_all_rtt:
            if 0 < item < timeout:
                cls_rtt.append(item)
        step = timeout // bins
        sp = step / 2
        freq = pds.cut(cls_rtt, bins=[x for x in np.arange(0, timeout + 0.1, step)])
        freq = freq.value_counts().values
        rtt_x = [x for x in np.arange(sp, timeout, step)]
        rtt_y = [freq[rtt_x.index(x)] for x in rtt_x]
        plt.figure(figsize=figure_size)
        plt.title("class-index {} RTT frequency".format(cls_idx))
        plt.xlabel("Round-Trip Time(RTT) / ms")
        plt.ylabel("frequency")
        plt.plot(rtt_x, rtt_y, color="#D14D72", marker="o", linewidth=0.5, markersize=5)
        plt.hist(cls_rtt, bins=bins, color="#FCC8D1")
        plt.grid()
        plt.show()

    def drawDevice(self, device_name: str, timeout: int=120, bins: int=120, figure_size: tuple=(6, 4.5)):
        """
        绘制柱线混合图
        """
        rtt_all = self.__rtt_[device_name]
        rtt = list()
        for item in rtt_all:
            if 0 < item < timeout:
                rtt.append(item)
        step = timeout // bins
        sp = step / 2
        freq = pds.cut(rtt, bins=[x for x in np.arange(0, timeout + 0.1, step)])
        freq = freq.value_counts().values
        rtt_x = [x for x in np.arange(sp, timeout, step)]
        rtt_y = [freq[rtt_x.index(x)] for x in rtt_x]
        plt.figure(figsize=figure_size)
        plt.title("{} RTT frequency distribution".format(device_name))
        plt.xlabel("Round-Trip Time(RTT) / ms")
        plt.ylabel("frequency")
        plt.plot(rtt_x, rtt_y, color="#D14D72", marker="o", linewidth=0.5, markersize=5)
        plt.hist(rtt, bins=bins, color="#FCC8D1")
        plt.grid()
        plt.show()

