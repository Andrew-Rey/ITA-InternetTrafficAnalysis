"""
PcapParser测试
生成特征csv文件

finished
"""

from PcapParser import *

pcap_path_24h = "./data/part-24h.pcapng"
pcap_path_29h = "./data/part-29h.pcapng"
target_split_dir = "./data/traffic"
target_csv_dir = "./data/traffic_csv"

pp = PcapParser(
    tshark_path="D:/Wireshark/tshark.exe",
    target_csv_dir=target_csv_dir
)

# split_pcaps = pp.split()
pcaps_24h = os.listdir("./data/traffic/24h")
pcaps_29h = os.listdir("./data/traffic/29h")
# print(pcaps_24h, pcaps_29h)

idx = 0
for p24 in pcaps_24h:
    csv_path = target_csv_dir + '/' + p24.split('/')[-1].split('.')[0] + "_" + str(idx) + ".csv"
    print("{} -> {}".format(p24, csv_path))
    pp.parse(target_csv=csv_path, pcap_path="./data/traffic/24h/" + p24)
    idx += 1

idx = 0
for p29 in pcaps_29h:
    csv_path = target_csv_dir + '/' + p29.split('/')[-1].split('.')[0] + "_" + str(idx) + ".csv"
    print("{} -> {}".format(p29, csv_path))
    pp.parse(target_csv=csv_path, pcap_path="./data/traffic/29h/" + p29)
    idx += 1
