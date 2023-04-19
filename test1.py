from ParsePcap import PcapParser

pp = PcapParser(
    pcap_path="./data/test.pcap",
    csv_path="",
    tshark_path="D:/Wireshark/tshark.exe"
)
pp.parse()