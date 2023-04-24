"""
测试pylshash模块

traffic class at idx=0
traffic device name at idx=1
traffic [src_ip -> dst_ip] at [idx=2, idx=3]
traffic features start at idx=4

"""

import pandas as pds
import numpy as np
import matplotlib.pyplot as plt
from lshash.lshash import LSHash

np.set_printoptions(threshold=np.inf)

data_path = "./data/test_csv/test.csv"
tfc_attr_df = pds.read_csv(filepath_or_buffer=data_path, sep=',', header=None, encoding="utf-8").fillna(0)
tfc_ary = tfc_attr_df.to_numpy()
base = 4
tfc_count, col = tfc_ary.shape
max_offset = col - base
# feature : [base : base + max_offset] 前闭后开
# print((raw, col))
print(tfc_ary[0])

hash_size = 10
lsh = LSHash(hash_size=hash_size, input_dim=max_offset)
for item in tfc_ary:
    lsh.index(item[base : base + max_offset])
res = lsh.query([51, 23990, 4, 32, 0, 0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10010.0, 10010.0, 31.0, 19847.0,
 349.0, 0.0, 0.0, 0.0, 0.0])
# [((data), score), ((data), score), ...]
print(res[1][1])

