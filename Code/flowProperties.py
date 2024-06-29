from scapy.all import *
import os
import csv

di_name = "BitTorrent"
protocol = "BIT_TORRENT"

for i in range(2):
    rows_to_write = []
    if(i==0):
        dir_name=di_name+'-Tr'
    else:
        dir_name=di_name+'-Ts'
    pcap_files = os.listdir(dir_name)
    for pcap_file in pcap_files:
        packets=rdpcap(f'./{dir_name}/{pcap_file}')

        TCP_DICT = {}
        UDP_DICT = {}

        def InitializeParameters():
            tmp = {
                "packet_cnt": 0,
                "payload_size": 0,
                "flow_size": 0,
                "arr_time": 0,
                "dst_time": 0,
                "src_port": 100000,
                "dst_port": 100000,
            }
            return tmp

        def CreateNewDict(hash, index):
            tmp = {
                0: InitializeParameters(),
                1: InitializeParameters(),
            }
            # 1-TCP
            # 0-UDP
            if index == 1:
                TCP_DICT.update({hash: tmp})
            else:
                UDP_DICT.update({hash: tmp})

        def get_ratio(index, flow, property):
            # 1-TCP
            # 0-UDP
            if (index == 1):
                try:
                    ratio = TCP_DICT[flow][0][property]/TCP_DICT[flow][1][property]
                except ZeroDivisionError:
                    ratio = 0
            else:
                try:
                    ratio = UDP_DICT[flow][0][property]/UDP_DICT[flow][1][property]
                except ZeroDivisionError:
                    ratio = 0
            ratio = float("{:.2f}".format(ratio))
            return ratio

        for packet in packets:
            if TCP in packet:
                add1 = packet[IP].src
                add2 = packet[IP].dst
                port1 = packet[TCP].sport
                port2 = packet[TCP].dport

                info1 = [add1, port1]
                info2 = [add2, port2]

                if (info1[0] > info2[0]):  # 0 ascending, 1 descending
                    index_changed = 1
                    info1, info2 = info2, info1
                else:
                    index_changed = 0

                hash = info1[0]+' '+str(info1[1])+' '+info2[0]+' '+str(info2[1])

                if hash not in TCP_DICT:
                    CreateNewDict(hash, 1)

                if TCP_DICT[hash][index_changed]["packet_cnt"] == 0:
                    TCP_DICT[hash][index_changed]["arr_time"] = float(packet.time)

                TCP_DICT[hash][index_changed]["packet_cnt"] += 1
                TCP_DICT[hash][index_changed]["payload_size"] += len(packet[TCP].payload)
                TCP_DICT[hash][index_changed]["flow_size"] += len(packet)
                TCP_DICT[hash][index_changed]["dst_time"] = float(packet.time)
                TCP_DICT[hash][index_changed]["src_port"] = port1
                TCP_DICT[hash][index_changed]["dst_port"] = port2

            if UDP in packet:
                add1 = packet[IP].src
                add2 = packet[IP].dst
                port1 = packet[UDP].sport
                port2 = packet[UDP].dport

                info1 = [add1, port1]
                info2 = [add2, port2]

                if (info1[0] > info2[0]):  # 0 ascending, 1 descending
                    index_changed = 1
                    info1, info2 = info2, info1
                else:
                    index_changed = 0

                hash = info1[0]+' '+str(info1[1])+' '+info2[0]+' '+str(info2[1])

                if hash not in UDP_DICT:
                    CreateNewDict(hash, 0)

                if UDP_DICT[hash][index_changed]["packet_cnt"] == 0:
                    UDP_DICT[hash][index_changed]["arr_time"] = float(packet.time)

                UDP_DICT[hash][index_changed]["packet_cnt"] += 1
                UDP_DICT[hash][index_changed]["payload_size"] += len(packet[UDP].payload)
                UDP_DICT[hash][index_changed]["flow_size"] += len(packet)
                UDP_DICT[hash][index_changed]["dst_time"] = float(packet.time)
                UDP_DICT[hash][index_changed]["src_port"] = port1
                UDP_DICT[hash][index_changed]["dst_port"] = port2

        for flow in TCP_DICT:
            new_row = []
            if (TCP_DICT[flow][0]["arr_time"] > TCP_DICT[flow][1]["arr_time"]):
                TCP_DICT[flow][0], TCP_DICT[flow][1] = TCP_DICT[flow][1], TCP_DICT[flow][0]
            
            if(TCP_DICT[flow][0]["src_port"]==100000):
                TCP_DICT[flow][0], TCP_DICT[flow][1] = TCP_DICT[flow][1], TCP_DICT[flow][0]

            PacketCountRatio = get_ratio(1,flow,"packet_cnt")
            PayloadSizeRatio = get_ratio(1,flow,"payload_size")
            FlowLengthRatio = get_ratio(1,flow,"flow_size")

            src_port=TCP_DICT[flow][0]["src_port"]
            dst_port=TCP_DICT[flow][0]["dst_port"]

            FlowDuration0 = TCP_DICT[flow][0]["dst_time"]-TCP_DICT[flow][0]["arr_time"]
            FlowDuration1 = TCP_DICT[flow][1]["dst_time"]-TCP_DICT[flow][1]["arr_time"]

            if(FlowDuration0 ==0 or FlowDuration1==0):
                FlowDurationRatio = 0
                FlowPacketRateRatio = 0
            else:
                FlowDurationRatio = FlowDuration0/FlowDuration1
                FlowPacketRateRatio0 = TCP_DICT[flow][0]["packet_cnt"]/FlowDuration0
                FlowPacketRateRatio1 = TCP_DICT[flow][1]["packet_cnt"]/FlowDuration1
                FlowPacketRateRatio = FlowPacketRateRatio0/FlowPacketRateRatio1
                FlowDurationRatio = float("{:.2f}".format(FlowDurationRatio))
                FlowPacketRateRatio = float("{:.2f}".format(FlowPacketRateRatio))

            new_row =[
                flow,
                PacketCountRatio,
                PayloadSizeRatio,
                FlowDurationRatio,
                FlowPacketRateRatio,
                FlowLengthRatio,
                src_port,
                dst_port
            ]

            # print(flow,PacketCountRatio,PayloadSizeRatio ,FlowDurationRatio,FlowPacketRateRatio,FlowLengthRatio,src_port,dst_port)

            new_row.append(protocol)
            rows_to_write.append(new_row)

        for flow in UDP_DICT:
            new_row = []
            if (UDP_DICT[flow][0]["arr_time"] > UDP_DICT[flow][1]["arr_time"]):
                UDP_DICT[flow][0],UDP_DICT[flow][1] = UDP_DICT[flow][1],UDP_DICT[flow][0]
            
            if(UDP_DICT[flow][0]["src_port"]==100000):
                UDP_DICT[flow][0], UDP_DICT[flow][1] = UDP_DICT[flow][1], UDP_DICT[flow][0]

            PacketCountRatio = get_ratio(0,flow,"packet_cnt")
            PayloadSizeRatio = get_ratio(0,flow,"payload_size")
            FlowLengthRatio = get_ratio(0,flow,"flow_size")

            src_port=UDP_DICT[flow][0]["src_port"]
            dst_port=UDP_DICT[flow][0]["dst_port"]

            FlowDuration0 = UDP_DICT[flow][0]["dst_time"]-UDP_DICT[flow][0]["arr_time"]
            FlowDuration1 = UDP_DICT[flow][1]["dst_time"]-UDP_DICT[flow][1]["arr_time"]

            if(FlowDuration0 ==0 or FlowDuration1==0):
                FlowDurationRatio = 0
                FlowPacketRateRatio = 0
            else:
                FlowDurationRatio = FlowDuration0/FlowDuration1
                FlowPacketRateRatio0 = UDP_DICT[flow][0]["packet_cnt"]/FlowDuration0
                FlowPacketRateRatio1 = UDP_DICT[flow][1]["packet_cnt"]/FlowDuration1
                FlowPacketRateRatio = FlowPacketRateRatio0/FlowPacketRateRatio1
                FlowDurationRatio = float("{:.2f}".format(FlowDurationRatio))
                FlowPacketRateRatio = float("{:.2f}".format(FlowPacketRateRatio))

            new_row =[
                flow,
                PacketCountRatio,
                PayloadSizeRatio,
                FlowDurationRatio,
                FlowPacketRateRatio,
                FlowLengthRatio,
                src_port,
                dst_port
            ]

            new_row.append(protocol)
            rows_to_write.append(new_row)


    tmp=["Flow","Packet Count Ratio","Payload Size Ratio","Flow Duration Ratio","Flow Packet Rate Ratio","Flow Length Ratio",
        "Source Port","Destination Port","Class Label"]
    if(i==0):
        to_write="FlowPropertiesTraining.csv"
    else:
        to_write="FlowPropertiesTesting.csv"

    with open(to_write, 'a', newline='') as file:
        writer = csv.writer(file)
        # writer.writerow(tmp)
        for row in rows_to_write:
            writer.writerow(row)
