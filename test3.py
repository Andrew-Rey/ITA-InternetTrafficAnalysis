import pyshark

cap = pyshark.FileCapture(input_file="./data/test.pcap", tshark_path="D:/Wireshark/tshark.exe", display_filter='ip')
for pkg in cap:
    print(pkg.udp)
