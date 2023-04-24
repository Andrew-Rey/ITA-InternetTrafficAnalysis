# pyshark测试

import os
import pyshark

print(os.path.abspath('./data/test.pcap'))

# cap = pyshark.FileCapture(input_file="./data/test.pcap", tshark_path="D:/Wireshark/tshark.exe", only_summaries=True)
# print("-" * 50, "capture:")
# for item in dir(cap):
#     print(item)

# for pkg in cap:
#     print(pkg)

# pkg = cap[0]
# print(pkg.ip.field_names)
# print(type(pkg))
# print('ip' in pkg)
# for i in range(3):
# pkg1 = cap.next()
# print(pkg1)
# print(len(cap))
# pkg2 = cap.next()
# print(pkg2)
# print("-" * 50, "packet:")
# for item in dir(pkg):
#     print(item)
# print(pkg.transport_layer)

# ip = pkg.ip
# print("-" * 50, "ip:")
# for item in dir(ip):
#     print(item)
# ip.pretty_print()
# print(ip.checksum)
# print(ip.id)
# print(ip.proto)
# print(ip.flags_df) 
# print(ip.dsfield_dscp, ip.dsfield_ecn)
# print(ip.raw_mode)

# tcp = pkg.tcp
# print("-" * 50, "tcp:")
# for item in dir(tcp):
#     print(item)
# tcp.pretty_print()
# print(tcp.checksum)
# print(tcp.time_delta)
# print(tcp.window_size_scalefactor)
# print(tcp.layer_name)

# udp = pkg.udp
# print("-" * 50, "udp:")
# for item in dir(udp):
#     print(item)
# udp.pretty_print()

# tls = pkg.tls
# print("-" * 50, "tls:")
# for item in dir(tls):
#     print(item)
# print(tls.record_content_type)
# tls.pretty_print()


