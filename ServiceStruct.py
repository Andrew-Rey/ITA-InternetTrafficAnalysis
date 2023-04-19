"""
define the structures of protocols
most of the attributes are int, some are float
among these attributes, same are 2-value
for encoding of these protocols: 0 stands for not exists, 1 for exists
"""


class Params(object):
    def __init__(self) -> None:
        self.device_name_ = None  # str
        self.exist_ip_ = None     # int: 0 | 1
        self.exist_tcp_ = None    # int: 0 | 1
        self.exist_udp_ = None    # int: 0 | 1
        self.exist_tls_ = None    # int: 0 | 1

class IpParams(Params):
    def __init__(self) -> None:
        super().__init__()
        self.exist_ip_ = True
        self.ip_src_ = None
        self.ip_dst_ = None
        self.ip_chk_ = None
        self.ip_version_ = None
        self.ip_len_ = None
        self.ip_ttl_ = None
        self.ip_df_ = None
        self.ip_mf_ = None
        self.ip_rb_ = None
        self.ip_dscp_ = None
        self.ip_ecn_ = None

class TcpParams(Params):
    def __init__(self) -> None:
        super().__init__()
        self.exist_tcp_ = True
        self.tcp_srcport_ = None
        self.tcp_dstport_ = None
        self.tcp_chk_ = None
        self.tcp_load_ = None
        self.tcp_len_ = None
        self.tcp_seglen_ = None
        self.tcp_winsize_ = None
        self.tcp_time_delta_ = None
        self.tcp_time_relative_ = None

class UdpParams(Params):
    def __init__(self) -> None:
        super().__init__()
        self.exist_udp_ = True
        self.udp_srcport_ = None
        self.udp_dstport_ = None
        self.udp_chk_ = None
        self.udp_load_ = None
        self.udp_len_ = None
        self.udp_time_delta_ = None
        self.udp_time_relative_ = None

class TlsParams(Params):
    def __init__(self) -> None:
        super().__init__()
        self.exist_tls_ = True
        self.tls_len_ = None
        self.tls_record_version_ = None



