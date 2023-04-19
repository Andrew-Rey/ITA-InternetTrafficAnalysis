import os
import sys
import pyshark

from ServiceStruct import *

class PcapParser(object):
    def __init__(self, pcap_path: str, csv_path: str, tshark_path: str, target_split_dir: str=None) -> None:
        self.__pcap_path_ = pcap_path
        self.__csv_path_ = csv_path
        self.__tshark_path_ = tshark_path
        self.__target_split_dir_ = target_split_dir

    def split(self, target_dir: str, split_size: int):
        self.__target_split_dir_ = target_dir
        pass

    def parseSmall(self, pcap_file: str=None):
        # parse one small pcap file
        file = self.__pcap_path_
        if pcap_file is not None:
            file = pcap_file
        

    def parseAll(self, target_dir: str=None):
        # parse files in dir, if param:target_dir is not None, then parse there; else parse self.target_split_dir
        dir = self.__target_split_dir_
        if target_dir is not None:
            dir = target_dir
