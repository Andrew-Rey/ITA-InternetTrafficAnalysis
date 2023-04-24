# ITA-InternetTrafficAnalysis
Internet traffic analysis for IoT devices.

## PCAP文件格式

`pcap header(global) | packet header1 | packet data1 | packet header2 | packet data2 | ...`

`pcap header(global)`: 定义了整个文件的信息

`pcaket header i`: 定义了每条流量包的包头

`packet data i`: 即为真正的数据, 格式与标准网络协议格式一致

选取的特征定义在ServiceStruct中.

> 关于如何查看某一层协议的属性: 用`python`内置的`dir()`即可, 要注意先判断协议是否存在

> **小trick:**
>
> 大的pcap文件分割为小文件

```python
os.system("editcap -c {} {} {}".format(one_file_size, in_file, target_name))
```

将所有pcap提取特征后保存在csv中

## LSH
