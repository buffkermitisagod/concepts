from scapy.all import *
from threading import Thread
import pandas
import time
import os

'''
this is where we will search for ssid's and ther bssid's
this will then be procesed by pro.py and the result of that will be used in iphone_crash_wifi.py 

after this and when the attack is setup the script will also deuth people

'''
mac = []
ap = []

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

def callback(packet):
    try:
        if packet.haslayer(Dot11Beacon):
            # extract the MAC address of the network
            bssid = packet[Dot11].addr2
            makeb = bssid+"\n"
            try:
                x = mac.index(makeb)
            except Exception:
                mac.append(makeb)
            # get the name of it
            ssid = packet[Dot11Elt].info.decode()
            make = ssid+"\n"
            try:
                x = ap.index(make)
            except Exception:
                ap.append(make)
            # get the name
            try:
                dbm_signal = packet.dBm_AntSignal
            except:
                dbm_signal = "N/A"
            # extract network stats
            stats = packet[Dot11Beacon].network_stats()
            # get the channel of the AP
            channel = stats.get("channel")
            # get the crypto
            crypto = stats.get("crypto")
            networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)
            return mac, ap
    except KeyboardInterrupt:
        print("run")
        #print(mac)
        #print(ap)

def print_all():
    try:
        while True:
            os.system("clear")
            print(networks)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("run")
        #print(mac)
        #print(ap)


def change_channel():
    try:
        ch = 1
        while True:
            print("[-] changing channle ch("+str(ch)+")")
            os.system(f"iwconfig {iface} channel {ch}")
            # switch channel from 1 to 14 each 0.5s
            ch = ch % 14 + 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("run")
        #print(mac)
        #print(ap)


if __name__ == "__main__":
    try:
        # interface name, check using iwconfig
        i = open("config.txt","r").readlines()[2]
        i = i.split("=")
        iface = i[1]
        iface = iface.replace("\n","")
        # start the thread that prints all the networks
        printer = Thread(target=print_all)
        printer.daemon = True
        printer.start()
        # start the channel changer
        channel_changer = Thread(target=change_channel)
        channel_changer.daemon = True
        channel_changer.start()
        # start sniffing
        print("[-] sniffing....")
        sniff(prn=callback, iface=iface)
    except KeyboardInterrupt:
        print("run")
        #print(mac)
        #print(ap)
file = open("ap.txt","r+")
file.writelines(ap)
file.close()
file = open("mac.txt","r+")
file.writelines(mac)
file.close()