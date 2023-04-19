# ITA-InternetTrafficAnalysis
Internet traffic analysis for IoT devices.

## PCAP文件格式

`pcap header(global) | packet header1 | packet data1 | packet header2 | packet data2 | ...`

`pcap header(global)`: 定义了整个文件的信息

`pcaket header i`: 定义了每条流量包的包头

`packet data i`: 即为真正的数据, 格式与标准网络协议格式一致

