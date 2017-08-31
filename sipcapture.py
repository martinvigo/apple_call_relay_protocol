import sys
import binascii
from scapy.all import *


iphone = "192.168.0.101"
kali = "192.168.0.102"
macbook = "192.168.0.105"
prismacbook = "192.168.0.104"
prisIphone = "192.168.0.106"

myPhonesport = 0
myPhonedport = 0


def processPackage(pkt):
	print "-------Packet received"
	#print binascii.hexlify(pkt.load)
	pkt.show()
	#pkt[IP].dst = iphone # Modify IP to point to attacker iPhone
	#pkt.dport = myPhonedport # Modify port to point to attacker's iPhone open port

	#send(pkt)	


myfilter = "src %s" % (prisIphone)
sniff(filter=myfilter, prn=processPackage)

