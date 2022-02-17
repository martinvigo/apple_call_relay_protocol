# Abusing Apple's Call Relay protocol
List of python scripts I used during my research into Apple's Call Relay protocol.

## Basic info
Apple introduced a new set of features in iOS 8 and Yosemite under the name "Continuity". These features allow iPhones to work with other iDevices such as Macs and iPads in new ways. Handoff, Instant Hotspot and Airdrop are some of the new services offered by Continuity. Among these new services is one named "Call Relay". Essentially, it allows one to make and receive phone calls via iDevices and route them through the iPhone. This is not your typical VOIP service but a P2P connection based on a proprietary protocol. Apple's security white-paper is short and vague on this particular topic. Only four paragraphs are dedicated to explain how Call Relay works and the only security relevant information is as follows: "The audio will be seamlessly transmitted from your iPhone using a secure peer- to-peer connection between the two devices."

I reverse engineered the protocol to understand how it works. The goal was to see if Apple's design was secure and find vulnerabilities focusing on ways to eavesdrop phone calls. It is possible to abuse the protocol to spy on victims by leaving their microphone open. It is also possible to troll victims by dropping or preventing them from picking up phone calls. Last, an attacker can abuse multi-party calls to impersonate other callers.

More info: https://www.martinvigo.com/diy-spy-program-abusing-apple-call-relay-protocol

## Demo video
##### DIY spy program: Abusing Apple's Call Relay Protocol. Spying on victims demo
[![DIY spy program: Abusing Apple's Call Relay Protocol. Spying on victims demo](https://img.youtube.com/vi/zx0wDshqb7o/0.jpg)](https://www.youtube.com/watch?v=zx0wDshqb7o)
##### DIY spy program: Abusing Apple's Call Relay Protocol. Multiparty call demo
[![DIY spy program: Abusing Apple's Call Relay Protocol. Multiparty call demo](https://img.youtube.com/vi/vsHGL8lDsho/0.jpg)](https://www.youtube.com/watch?v=vsHGL8lDsho)

## Talk at Kasperky's Security Analyst Summit 2017
[![Do-it-yourself spy program: Abusing Apple's Call Relay protol](https://img.youtube.com/vi/xjDcmaEqPTw/0.jpg)](https://www.youtube.com/watch?v=xjDcmaEqPTw)

## Authors
Martin Vigo - @martin_vigo - [martinvigo.com](https://www.martinvigo.com)
