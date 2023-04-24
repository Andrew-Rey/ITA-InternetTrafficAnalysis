"""
pcap解析模块: 将pcap文件转为csv, 自行定义了特征, 并全部转化为int, 文件的结构如下

class                 idx=0
device name           idx=1
[src_ip -> dst_ip]    idx=2 to idx=3
features              idx=4 to tail

"""


import os
import pyshark

from ServiceStruct import IpParams, TcpParams, UdpParams, TlsParams
from DeviceMap import device_map

class PcapParser(object):
    def __init__(
            self,
            pcap_path: str=None,
            target_split_dir: str=None,
            target_csv_dir: str=None, 
            tshark_path: str=None, 
            base_filter: str='ip'
        ) -> None:
        """pcap_path(one huge file) -> target_split_dir/**.pcap(multiple files) -> target_csv_dir/**.csv(multiple files)
        """
        self.__pcap_path_ = pcap_path
        self.__target_split_dir_ = target_split_dir
        self.__target_csv_dir_ = target_csv_dir
        self.__tshark_path_ = tshark_path
        self.__base_filter_ = base_filter
        
        if self.__pcap_path_ is not None:
            self.__pcap_path_ = self.__pcap_path_.replace("\\", '/')
        if self.__target_csv_dir_ is not None:
            self.__target_csv_dir_ = self.__target_csv_dir_.replace("\\", '/')
        if self.__target_split_dir_ is not None:
            self.__target_split_dir_ = self.__target_split_dir_.replace("\\", '/')

        if self.__target_split_dir_ is not None and not os.path.exists(self.__target_split_dir_):
            os.mkdir(self.__target_split_dir_)
        if self.__target_csv_dir_ is not None and not os.path.exists(self.__target_csv_dir_):
            os.mkdir(self.__target_csv_dir_)

        if self.__tshark_path_ is None:
            print(">> can't find tshark")
    
    def split(self, one_file_size: int=1000, pcap_path: str=None, target_split_dir: str=None):
        """pcap_path(one file) -> target_split_dir/**.pcap (multiple files)
        """
        out_dir = self.__target_split_dir_
        in_file = self.__pcap_path_
        if target_split_dir is not None:
            out_dir = target_split_dir
        if pcap_path is not None:
            in_file = pcap_path
        in_file = in_file.replace("\\", '/')
        out_dir = out_dir.replace("\\", '/')
        file_name = in_file.split('/')[-1]
        target_name = out_dir + '/' + file_name
        os.system("editcap -c {} {} {}".format(one_file_size, in_file, target_name))
        print(">> split {} in dir {}, size-per-file {}".format(in_file, out_dir, one_file_size))
        return [os.path.abspath(out_dir + '/' + f).replace("\\", "/") for f in os.listdir(out_dir)]

    def parse(self, target_csv: str=None, pcap_path: str=None, base_filter: str='ip'):
        """pcap_path(one file) -> target_csv(one file)
        """
        in_file = self.__pcap_path_
        out_file = "./default.csv"
        if in_file is not None:
            out_file = self.__target_csv_dir_ + in_file.split('/')[-1].split('.')[0] + ".csv"
        b_filter = self.__base_filter_
        if pcap_path is not None:
            in_file = pcap_path
            out_file = self.__target_csv_dir_ + in_file.split('/')[-1].split('.')[0] + ".csv"
        if target_csv is not None:
            out_file = target_csv
        if base_filter is not None:
            b_filter = base_filter
        if in_file is None or out_file is None:
            print(">> pcap file path or csv file path is not specified")
            return
        in_file = in_file.replace("\\", '/')
        out_file = out_file.replace("\\", '/')
        cap = pyshark.FileCapture(
            input_file=in_file, 
            tshark_path=self.__tshark_path_, 
            only_summaries=False,
            display_filter=b_filter
        )
        for packet in cap:
            attr = self.__attributes(pkt=packet)
            self.__tocsv(attr_tuple=attr, out_file=out_file)
        cap.close()

    def __name(self, ip_both: tuple):
        ip = ""
        if ip_both[0] in device_map:
            ip = ip_both[0]
        elif ip_both[1] in device_map:
            ip = ip_both[1]
        else:
            return "none"
        return device_map[ip]["value"]
    
    def __category(self, ip_both: tuple):
        ip = ""
        if ip_both[0] in device_map:
            ip = ip_both[0]
        elif ip_both[1] in device_map:
            ip = ip_both[1]
        else:
            return -1
        return device_map[ip]["class"]

    def __attributes(self, pkt):
        device_class = -1
        device_name = "none"
        ip_params = IpParams()
        tcp_params = TcpParams()
        udp_params = UdpParams()
        tls_params = TlsParams()
        if 'ip' in pkt:
            ip_pkt = pkt.ip
            ip_params.ip_chk_ = int(ip_pkt.checksum, 16)  # hex(16 base) -> int(10 base)
            ip_params.ip_df_ = ip_pkt.flags_df
            ip_params.ip_dscp_ = ip_pkt.dsfield_dscp
            ip_params.ip_dst_ = ip_pkt.dst
            ip_params.ip_ecn_ = ip_pkt.dsfield_ecn
            ip_params.ip_len_ = ip_pkt.len
            ip_params.ip_mf_ = ip_pkt.flags_mf
            ip_params.ip_rb_ = ip_pkt.flags_rb
            ip_params.ip_src_ = ip_pkt.src
            ip_params.ip_ttl_ = ip_pkt.ttl
            ip_params.ip_version_ = ip_pkt.version
            device_class = self.__category((ip_params.ip_src_, ip_params.ip_dst_))
            device_name = self.__name((ip_params.ip_src_, ip_params.ip_dst_))
        if 'tcp' in pkt:
            tcp_pkt = pkt.tcp
            tcp_params.tcp_chk_ = int(tcp_pkt.checksum, 16)
            tcp_params.tcp_dstport_ = tcp_pkt.dstport
            tcp_params.tcp_len_ = tcp_pkt.len
            if tcp_pkt.payload is not None:
                tcp_params.tcp_load_ = sum([int(l, 16) for l in tcp_pkt.payload.split(':')[:4]])  # load字段取前缀和
            tcp_params.tcp_srcport_ = tcp_pkt.srcport
            tcp_params.tcp_time_delta_ = tcp_pkt.time_delta
            tcp_params.tcp_time_relative_ = tcp_pkt.time_relative
            tcp_params.tcp_winsize_ = tcp_pkt.window_size
        if 'udp' in pkt:
            udp_pkt = pkt.udp
            udp_params.udp_chk_ = int(udp_pkt.checksum, 16)
            udp_params.udp_dstport_ = udp_pkt.dstport
            udp_params.udp_len_ = udp_pkt.length
            if udp_pkt.payload is not None:
                udp_params.udp_load_ = sum([int(l, 16) for l in udp_pkt.payload.split(':')[:4]])  # load字段取前缀和
            udp_params.udp_srcport_ = udp_pkt.srcport
            udp_params.udp_time_delta_ = udp_pkt.time_delta
            udp_params.udp_time_relative_ = udp_pkt.time_relative
        if 'tls' in pkt:
            tls_pkt = pkt.tls
            tls_params.tls_len_ = tls_pkt.record_length
            # tls_params.tls_record_version_ = int(tls_pkt.record_version, 16)
            # tls_params.tls_record_content_type_ = tls_pkt.record_content_type
        return (device_class, device_name, ip_params, tcp_params, udp_params, tls_params)
        
    def __tocsv(self, attr_tuple: tuple, out_file: str, mode: str='a'):
        fmt = "{}," * 29
        with open(out_file, mode=mode) as csvf:
            csvf.write(
                fmt.format(
                
                    attr_tuple[0],             # class
                    attr_tuple[1],             # device name

                    attr_tuple[2].ip_src_,     # 2
                    attr_tuple[2].ip_dst_,     # 3
                    attr_tuple[2].ip_len_,     # 4
                    attr_tuple[2].ip_chk_,     # 5
                    attr_tuple[2].ip_version_, # 6
                    attr_tuple[2].ip_ttl_,     # 7
                    attr_tuple[2].ip_df_,      # 8
                    attr_tuple[2].ip_mf_,      # 9
                    attr_tuple[2].ip_rb_,      # 10
                    attr_tuple[2].ip_dscp_,    # 11
                    attr_tuple[2].ip_ecn_,     # 12

                    attr_tuple[3].tcp_srcport_,# 13
                    attr_tuple[3].tcp_dstport_,# 14
                    attr_tuple[3].tcp_len_,    # 15
                    attr_tuple[3].tcp_chk_,    # 16
                    attr_tuple[3].tcp_winsize_,# 17
                    attr_tuple[3].tcp_load_,   # 18
                    attr_tuple[3].tcp_time_delta_,    # 19
                    attr_tuple[3].tcp_time_relative_, # 20

                    attr_tuple[4].udp_srcport_,# 21
                    attr_tuple[4].udp_dstport_,# 22
                    attr_tuple[4].udp_len_,    # 23
                    attr_tuple[4].udp_chk_,    # 24
                    attr_tuple[4].udp_load_,   # 25
                    attr_tuple[4].udp_time_delta_,    # 26
                    attr_tuple[4].udp_time_relative_, # 27

                    attr_tuple[5].tls_len_,    # 28
                    # attr_tuple[5].tls_record_version_,# 29
                    # attr_tuple[5].tls_record_content_type_  # 30

                ) + "\n"
            )


if __name__ == "__main__":
    pcap_path = "./data/test.pcapng"
    target_split_dir = "./data/test"
    target_csv_dir = "./data/test_csv"

    pp = PcapParser(
        pcap_path=pcap_path,
        tshark_path="D:/Wireshark/tshark.exe",
        target_split_dir=target_split_dir,
        target_csv_dir=target_csv_dir
    )

    split_pcaps = pp.split()
    idx = 0
    for pcap in split_pcaps:
        csv_path = target_csv_dir + '/' + pcap.split('/')[-1].split('.')[0] + "_" + str(idx) + ".csv"
        print("{} -> {}".format(pcap, csv_path))
        pp.parse(target_csv=csv_path, pcap_path=pcap)
        idx += 1