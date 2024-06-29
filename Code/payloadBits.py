from scapy.all import  * 
import os
import csv

di_name = "SSH"
protocol_id = di_name

for j in range(2):
    rows_to_write = []
    if(j==0):
        dir_name=di_name+'-Tr'
    else:
        dir_name=di_name+'-Ts'
        
    pcap_files = os.listdir(dir_name)

    for pcap_file in pcap_files:
        packets=rdpcap(f'./{dir_name}/{pcap_file}')

        TCP_DICT={}
        UDP_DICT={}
        i=-1

        def decimalToBinary(n):
            tmp=bin(n).replace("0b", "")
            while(len(tmp))<8:
                tmp='0'+tmp
            return tmp
            
        for packet in packets:
            i=i+1
            if TCP in packet:
                add1=packet[IP].src
                add2=packet[IP].dst
                port1=packet[TCP].sport
                port2=packet[TCP].dport

                info1=[add1,port1]
                info2=[add2,port2]

                if(info1[0]>info2[0]):
                    info1,info2 =info2, info1
                hash=info1[0]+' '+str(info1[1])+' '+info2[0]+' '+str(info2[1])

                if hash in TCP_DICT:
                    TCP_DICT[hash].append(i)
                else:
                    TCP_DICT.update({hash: [i]})

            if UDP in packet:
                layer=packet.getlayer(1)
                add1=layer.src
                add2=layer.dst
                port1=packet[UDP].sport
                port2=packet[UDP].dport

                info1=[add1,port1]
                info2=[add2,port2]

                if(info1[0]>info2[0]):
                    info1,info2 =info2, info1
                hash=info1[0]+' '+str(info1[1])+' '+info2[0]+' '+str(info2[1])

                if hash in UDP_DICT:
                    UDP_DICT[hash].append(i)
                else:
                    UDP_DICT.update({hash: [i]})

        for stream in TCP_DICT:
            cnt=0
            requirement_satisfied=False
            new_row=[]
            for ind in TCP_DICT[stream]:
                if(requirement_satisfied):
                    break;
                payload=raw(packets[ind][TCP].payload)
                if(payload):
                    for byte in payload:
                        if(requirement_satisfied):
                            break
                        else:
                            binary_string=decimalToBinary(byte)
                            for i in range(8):
                                new_row.append(binary_string[i])
                            cnt=cnt+1
                            if(cnt==4):
                                requirement_satisfied=True
            
            if requirement_satisfied:
                new_row.append(protocol_id)
                rows_to_write.append(new_row)

        for stream in UDP_DICT:
            cnt=0
            requirement_satisfied=False
            new_row=[]
            for ind in UDP_DICT[stream]:
                if(requirement_satisfied):
                    break;
                payload=raw(packets[ind][UDP].payload)
                if(payload):
                    for byte in payload:
                        if(requirement_satisfied):
                            break
                        else:
                            binary_string=decimalToBinary(byte)
                            for i in range(8):
                                new_row.append(binary_string[i])
                            cnt=cnt+1
                            if(cnt==4):
                                requirement_satisfied=True

            if requirement_satisfied:
                new_row.append(protocol_id)
                rows_to_write.append(new_row)

    if(j==0):
        to_write="PayLoadBitsTraining.csv"
    else:
        to_write="PayLoadBitsTesting.csv"

    tmp=[]
    for i in range(32):
        tmp.append(i+1)
    tmp.append("protocol")

    with open(to_write, 'a', newline='') as file:
        writer = csv.writer(file)
        # writer.writerow(tmp)
        for row in rows_to_write:
            writer.writerow(row)


        
    
