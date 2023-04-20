import os
import sys
import pyshark

from ServiceStruct import *

class PcapParser(object):
    def __init__(
            self, pcap_path: str=None, 
            target_csv_dir: str=None, 
            tshark_path: str=None, 
            base_filter: str='ip'
        ) -> None:
        self.__pcap_path_ = pcap_path
        self.__target_csv_dir_ = target_csv_dir
        self.__tshark_path_ = tshark_path
        self.__pcap_ext_ = self.__pcap_path_.split('.')[-1]
        self.__base_filter_ = base_filter
        
        self.__pcap_path_ = self.__pcap_path_.replace("\\", '/')
        self.__target_csv_dir_ = self.__target_csv_dir_.replace("\\", '/')

        if self.__tshark_path_ is None:
            print(">> can't find tshark")
        
    def split(self, split_size: int=None, target_csv_dir: str=None, pcap_path: str=None, base_filter: str='ip'):
        in_file = self.__pcap_path_
        ext = self.__pcap_ext_
        out_dir = self.__target_csv_dir_
        b_filter = self.__base_filter_
        if pcap_path is not None:
            in_file = pcap_path
            ext = pcap_path.split('.')[-1]
        if target_csv_dir is not None:
            out_dir = target_csv_dir
        if base_filter is not None:
            b_filter = base_filter
        if in_file is None or out_dir is None:
            print(">> pcap file path or csv file path is not specified")
            return
        cap = pyshark.FileCapture(
            input_file=in_file, 
            tshark_path=self.__tshark_path_, 
            only_summaries=True, 
            display_filter=b_filter
        )
        file_count = 0
        packet_list = list()
        if not os.path.exists(out_dir):
            os.mkdir(out_dir)
        for packet in cap:
            packet_list.append(packet)
            file_count += 1
            if file_count == split_size:
                filename = in_file.split('/')[-1].split('.')[0]
                target_file = out_dir + '/' + filename + '_' + str(file_count // split_size) + '.' + ext
                # print(target_file)
                attr_tuple = self.__parse(packet_list=packet_list)
                self.__tocsv(attr_tuple=attr_tuple, out_file=target_file)
                packet_list = []
        # write remains
        if packet_list is not []:
            filename = in_file.split('/')[-1].split('.')[0]
            target_file = out_dir + '/' + filename + '_' + str(file_count // split_size) + '.' + ext
            # print(target_file)
            attr_tuple = self.__parse(packet_list=packet_list)
            self.__tocsv(attr_tuple=attr_tuple, out_file=target_file)

    def __parse(self, packet_list: list):
        if not packet_list:
            return
        ip_params = IpParams()
        tcp_params = TcpParams()
        udp_params = UdpParams()
        tls_params = TlsParams()
        for pkt in packet_list:
            if 'ip' in pkt:
                ip_pkt = pkt.ip
                ip_params.ip_chk_ = ip_pkt.checksum
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
            if 'tcp' in pkt:
                tcp_pkt = pkt.tcp
                tcp_params.tcp_chk_ = tcp_pkt.checksum
                tcp_params.tcp_dstport_ = tcp_pkt.dstport
                tcp_params.tcp_len_ = tcp_pkt.len
                tcp_params.tcp_load_ = tcp_pkt.payload
                tcp_params.tcp_srcport_ = tcp_pkt.srcport
                tcp_params.tcp_time_delta_ = tcp_pkt.time_delta
                tcp_params.tcp_time_relative_ = tcp_pkt.time_relative
                tcp_params.tcp_winsize_ = tcp_pkt.windowsize
            if 'udp' in pkt:
                udp_pkt = pkt.udp
                udp_params.udp_chk_ = udp_pkt.checksum
                udp_params.udp_dstport_ = udp_pkt.dstport
                udp_params.udp_len_ = udp_pkt.length
                udp_params.udp_load_ = udp_pkt.payload
                udp_params.udp_srcport_ = udp_pkt.srcport
                udp_params.udp_time_delta_ = udp_pkt.time_delta
                udp_params.udp_time_relative_ = udp_pkt.time_relative
            if 'tls' in pkt:
                tls_pkt = pkt.tls
                tls_params.tls_len_ = tls_pkt.record_length
                tls_params.tls_record_version_ = tls_pkt.record_version
                tls_params.tls_record_content_type_ = tls_pkt.record_content_type
        return (ip_params, tcp_params, udp_params, tls_params)
        
    def __tocsv(self, attr_tuple: tuple, out_file: str):
        fmt = ""
        for attr in attr_tuple:
            fmt += "{}," * len(dir(attr))
        print(fmt.format(
            attr_tuple[0].ip_chk_,
            attr_tuple[0].ip_df_,
            attr_tuple[0].ip_dscp_,
            attr_tuple[0].ip_dst_,
            attr_tuple[0].ip_ecn_,
            attr_tuple[0].ip_len_,
            attr_tuple[0].ip_mf_,
            attr_tuple[0].ip_rb_,
            attr_tuple[0].ip_src_,
            attr_tuple[0].ip_ttl_,
            attr_tuple[0].ip_version_,
            attr_tuple[1].tcp_chk_,
            attr_tuple[1].tcp_dstport_,
            attr_tuple[1].tcp_len_,
            attr_tuple[1].tcp_load_,
            attr_tuple[1].tcp_srcport_,
            attr_tuple[1].tcp_time_delta_,
            attr_tuple[1].tcp_time_relative_,
            attr_tuple[1].tcp_winsize_,
            attr_tuple[2].udp_chk_,
            attr_tuple[2].udp_dstport_,
            attr_tuple[2].udp_len_,
            attr_tuple[2].udp_load_,
            attr_tuple[2].udp_srcport_,
            attr_tuple[2].udp_time_delta_,
            attr_tuple[2].udp_time_relative_,
            attr_tuple[3].tls_len_,
            attr_tuple[3].tls_record_version_,
            attr_tuple[3].tls_record_content_type_
        ))
