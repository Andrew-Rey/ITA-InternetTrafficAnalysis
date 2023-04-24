"""
test sender
"""

from Samples import *

rtt_file = "./data/rtt.csv"
samples = Samples(read_file_path=rtt_file)
samples.fit()
samples.sample()
samples.drawCategory(0)
# samples.drawCategory(1)
# samples.drawCategory(2)
# samples.drawCategory(3)
# samples.drawCategory(4)
# samples.drawCategory(5)

sampled = samples.sample()
print(sampled)
# samples.drawDevice("yingfei")
# dn = sender.device_names_
# rtt = sender.load()
# draw_list = list()
# draw_list.append(dn[0])
# draw_list.append(dn[3])
# draw_list.append(dn[10])
# draw_list.append(dn[11])
# sender.draw(device_names_list=draw_list)
# sender.draw(device_names_list=draw_list)
# sender.draw3()
# sender.fit(device_names_list=draw_list)


