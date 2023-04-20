# 单函数测试

from PcapParser import PcapParser

pp = PcapParser(
    pcap_path="./data/test.pcap",
    csv_path="",
    tshark_path="D:/Wireshark/tshark.exe",
    target_split_dir="./data/test"
)

pp.split(split_size=20)
