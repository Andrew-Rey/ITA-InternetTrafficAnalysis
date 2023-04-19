import pyshark

cap = pyshark.FileCapture(input_file="./data/test312.pcapng", tshark_path="D:/Wireshark/tshark.exe")
print("-" * 50, "capture:")
for item in dir(cap):
    print(item)

pkg = cap[6]
print("-" * 50, "packet:")
for item in dir(pkg):
    print(item)
print(pkg.transport_layer)

ip = pkg.ip
print("-" * 50, "ip:")
for item in dir(ip):
    print(item)
ip.pretty_print()
print(ip.checksum)
# print(ip.id)
# print(ip.proto)
# print(ip.flags_df) 
# print(ip.dsfield_dscp, ip.dsfield_ecn)
# print(ip.raw_mode)

tcp = pkg.tcp
print("-" * 50, "tcp:")
for item in dir(tcp):
    print(item)
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

tls = pkg.tls
print("-" * 50, "tls:")
for item in dir(tls):
    print(item)
tls.pretty_print()

