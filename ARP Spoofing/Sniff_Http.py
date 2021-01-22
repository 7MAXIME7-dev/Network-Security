# -*- coding: utf-8 -*-
"""
Created on Mon Nov 23 11:43:48 2020

@author: maxim
"""

#!/usr/bin/python
from scapy.all import *

def http_header(packet):
        http_packet=str(packet)
        if http_packet.find('GET'):
                return GET_print(packet)

def GET_print(packet1):
    ret = "***************************************GET PACKET****************************************************\n"
    ret += "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    ret += "*****************************************************************************************************\n"
    return ret

sniff(prn=http_header, filter="tcp port 80")









