#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import struct
import time
import sys
import bluetooth
from colorama import Fore
import socket
import xml.etree.ElementTree as ET
import subprocess
def search_port(bdaddr,types):
    port = 0
    data = subprocess.run(f"sudo sdptool search --xml --bdaddr={bdaddr} {types}",
                          shell=True, stdout=subprocess.PIPE)
    xml_lines = []
    for line in data.stdout.split(b'\n'):
        if line.startswith(b'<') or line.startswith(b'\t'):
            xml_lines.append(line)

    xml_str = b''.join(xml_lines)
    try:
        tree = ET.fromstring(xml_str)
    except ET.ParseError:
        raise Exception("Error parsing XML SDP record")
    for elem in tree:
        if elem.tag == "attribute" and elem.attrib["id"] == "0x0004":
            port = int(elem[0][1][1].attrib["value"], 16)
    return port


hci = 'bluetooth0'
bdaddr = '22:22:D0:94:43:00'


psm_dict={
        'SDP': 0x01,
        'RFCOMM': 0x03,
        'BNEP': 0x0f,
        'HID': 0x11,
        'AVRCP': 0x17,
        'AVDTP': 0x19,
        'AVCTP': 0x1b,
          }
l2cap_list = list(psm_dict.keys())
obex_list = ['PBAP', 'MAP', 'FTP', 'OPUSH', 'HF']


# [L2CAP上层协议]
def L2CAP_Upper_Layer(protocol):
    try:
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        sock.settimeout(10)
        sock.connect((bdaddr, psm_dict[prot]))
        print(Fore.GREEN + f'{protocol}:{psm_dict[prot]}  Connect Success' + Fore.RESET)
        time.sleep(0.1)
        sock.close()
    except Exception:
        print(Fore.RED + f'No {protocol} Protocol')

def OBEX_Upper_Layer(protocol):
    try:
        self_port = search_port(bdaddr=bdaddr, types=protocol.lower())
        print(self_port)
        print(Fore.GREEN + f'{protocol}:{self_port}  Connect Success' + Fore.RESET)
    except Exception:
        print(Fore.RED + f'No {protocol} Protocol')


try:
    prot = sys.argv[1]
    if prot in l2cap_list:
        L2CAP_Upper_Layer(prot)
    elif prot in obex_list:
        OBEX_Upper_Layer(prot)
    else:
        print(f"所有协议名:\n\tL2CAP_Upper_Layer:{l2cap_list}\n\tOBEX_Upper_Layer:{obex_list}")
except IndexError:
    print(f"所有协议名:\n\tL2CAP_Upper_Layer:{l2cap_list}\n\tOBEX_Upper_Layer:{obex_list}")
