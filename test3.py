"""
PcapParser测试
"""

from PcapParser import *

pp = PcapParser(
    pcap_path="./data/part-29h.pcapng",
    target_csv_dir="./data/all",
    tshark_path="D:/Wireshark/tshark.exe",
)

pp.split(split_size=10000)
