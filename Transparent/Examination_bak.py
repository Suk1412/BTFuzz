#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import struct
from struct import pack
import sys
import bluetooth
from colorama import Fore
from scapy.compat import raw
from scapy.fields import BitField, ShortField, ByteField, X3BytesField, ByteEnumField, ConditionalField, StrLenField
from scapy.packet import Packet


import socket
import xml.etree.ElementTree as ET
import subprocess
sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
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


def _find_attr(xml_tree, attr_id):
    for elem in xml_tree:
        if elem.tag == "attribute" and elem.attrib["id"] == attr_id:
            elem = elem
            return elem
    raise Exception("Attribute %s not found!" % attr_id)

class AVCTP_Hdr(Packet):
    name = "AVCTP Command"
    fields_desc = [
        BitField("transaction", 1, 4),
        BitField("pkt_type", 0, 2),
        BitField("cr", 0, 1),
        BitField("ipid", 0, 1),
        ShortField("pid", 0x110e)
    ]


class AVRCP_Hdr(Packet):
    name = "AVRCP Command"
    fields_desc = [
        BitField("reserved", 0, 4),
        BitField("ctype", 1, 4),
        BitField("subtype", 9, 5),
        BitField("subid", 0, 3),
        ByteField("opcode", 0),
        ConditionalField(X3BytesField("cid", 0x001958), lambda pkt: pkt.opcode == 0),
        ConditionalField(ByteEnumField("pdu_id", 0x16, {0x10: "GetCapabilities",
                                                        0x11: "ListPlayerApplicationSettingAttributes",
                                                        0x12: "ListPlayerApplicationSettingValue",
                                                        0x13: "GetCurrentPlayerApplicationSettingValue",
                                                        0x14: "SetPlayerApplicationSettingValue",
                                                        0x15: "GetPlayerApplicationSettingAttributeText",
                                                        0x16: "GetPlayerApplicationSettingValueText",
                                                        0x17: "InformDisplayableCharacterSet",
                                                        0x18: "InformBatteryStatusOfCT",
                                                        0x20: "GetElementAttributes",
                                                        0x30: "GetPlayStatus",
                                                        0x31: "RegisterNotification",
                                                        0x40: "RequestContinuingResponse",
                                                        0x41: "AbortContinuingResponse",
                                                        0x50: "SetAbsoluteVolume",
                                                        0x60: "SetAddressedPlayer",
                                                        0x74: "PlayItem",
                                                        0x90: "AddToNowPlaying",

                                                        }), lambda pkt: pkt.opcode == 0),

        ConditionalField(BitField("rfa", 0, 6), lambda pkt: pkt.opcode == 0),
        ConditionalField(BitField("pkt_type", 0, 2), lambda pkt: pkt.opcode == 0),
        ConditionalField(ShortField("para_len", None), lambda pkt: pkt.opcode == 0),

        ConditionalField(BitField("page", 0, 5), lambda pkt: pkt.opcode == 0x31),
        ConditionalField(BitField("ex_code", 7, 3), lambda pkt: pkt.opcode == 0x31),

        ConditionalField(StrLenField("data", b""), lambda pkt: pkt.opcode == 0x30 or pkt.opcode == 0x31),

        ConditionalField(BitField("pushed", 0, 1), lambda pkt: pkt.opcode == 0x7c),
        ConditionalField(BitField("operation_id", 0, 7), lambda pkt: pkt.opcode == 0x7c),
        ConditionalField(ByteField("data_len", None), lambda pkt: pkt.opcode == 0x7c),

    ]

    def post_build(self, pkt, pay):  # type: (bytes, bytes) -> bytes
        if self.para_len is None and pay and self.opcode == 0:
            l = len(pay)
            pkt = pkt[:8] + pack('>H', l) + pkt[10:]
        elif self.data_len is None and pay and self.opcode == 0x7c:
            l = len(pay)
            pkt = pkt[:4] + pack('B', l) + pkt[5:]
        return pkt + pay


class AVRCP_GetCapabilities(Packet):
    # PDU_ID 0x10
    name = "GetCapabilities Command"
    fields_desc = [
        ByteField("capability_id", 2)
    ]

def sdp_pkt():
    sdp_pkt = b"\x02"  # PDU: Service Search Request (0x02) [0:1]
    sdp_pkt += b"\x00\x00"  # Transaction Id [1:3]
    sdp_pkt += b"\x00\x16"  # Parameter Length [3:5]
    sdp_pkt += b"\x35"  # Service Search Patten Type [5:6]
    sdp_pkt += b"\x03"  # Service Search Patten Size [6:7]
    sdp_pkt += b"\x19"  # Service Search Patten Data Type [7:8]
    sdp_pkt += b"\x11\x03"  # Service Search Patten Data Value [8:10]
    sdp_pkt += b"\xf0\x35"  # Record_Count [10:12]
    sdp_pkt += b"\x00"  # Continuation State [12:13]
    return sdp_pkt



hci = 'bluetooth0'
bdaddr = '22:22:D0:94:43:00'
sdp_psm = 0x01
rfcomm_psm = 0x03
bnep_psm = 0x0f
avrcp_psm = 0x17
avdtp_psm = 0x19
avctp_psm = 0x1b



# [L2CAP上层协议]
sdp_pkt = sdp_pkt()
def sdp_test(psm, pkt):
    try:
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        sock.settimeout(10)
        sock.connect((bdaddr, psm))
        print(Fore.GREEN + f'SDP:{psm}  Connect Success' + Fore.RESET)
        sock.send(pkt)
        sock.close()
    except Exception:
        print(Fore.RED + 'No SDP Protocol')

rfcomm_pkt = b'\x9b\xef\x1d\xff\x00\x0e\xcb\x00\x00\x00\x00\x4c\x00\x06\x09\x01\x00\x27'
def rfcomm_test(psm, pkt):
    try:
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        sock.settimeout(10)
        sock.connect((bdaddr, psm))
        print(Fore.GREEN + f'RFCOMM:{psm}  Connect Success' + Fore.RESET)
        sock.send(pkt)
        sock.close()
    except Exception:
        print(Fore.RED + 'No RFCOMM Protocol')

bnep_pkt = b'\x00""\xc5!\xd5\xb3\x8c\x88+\x00#\x8b\x00\x08\x01\x01\x01\x01\x01\x01\x01\x01'
def bnep_test(psm, pkt):
    try:
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        sock.settimeout(10)
        sock.connect((bdaddr, psm))
        print(Fore.GREEN + f'BNEP:{psm}  Connect Success' + Fore.RESET)
        sock.send(pkt)
        sock.close()
    except Exception:
        print(Fore.RED + 'No BNEP Protocol')

avrcp_pkt = b'\x10\x11\x0e\x01H\x00\x00\x19X\x16\x00\x00\x01\x02'
def avrcp_test(psm, pkt):
    try:
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        sock.settimeout(10)
        sock.connect((bdaddr, psm))
        print(Fore.GREEN + f'AVRCP:{psm}  Connect Success' + Fore.RESET)
        sock.send(pkt)
        sock.close()
    except Exception:
        print(Fore.RED + 'No AVRCP Protocol')

avdtp_pkt = b"\x40\x0a\x04" + b"\x41" * 10
def avdtp_test(psm, pkt):
    try:
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        sock.settimeout(10)
        sock.connect((bdaddr, psm))
        print(Fore.GREEN + f'AVDTP:{psm}  Connect Success' + Fore.RESET)
        sock.send(pkt)
        sock.recv(672)
        sock.close()
    except Exception:
        print(Fore.RED + 'No AVDTP Protocol')




#[RFCOMM上层协议]

# [OBEX上层协议]
def pbap_test(bdaddr):
    try:
        self_port = search_port(bdaddr=bdaddr, types='pbap')
        print(Fore.GREEN + f'PBAP:{self_port}  Connect Success' + Fore.RESET)
    except Exception:
        print(Fore.RED + 'No PBAP Protocol')

def map_test(bdaddr):
    try:
        self_port = search_port(bdaddr=bdaddr, types='map')
        print(Fore.GREEN + f'MAP:{self_port}  Connect Success' + Fore.RESET)
    except Exception:
        print(Fore.RED + 'No MAP Protocol')

def ftp_test(bdaddr):
    try:
        self_port = search_port(bdaddr=bdaddr, types='ftp')
        print(Fore.GREEN + f'FTP:{self_port}  Connect Success' + Fore.RESET)
    except Exception:
        print(Fore.RED + 'No FTP Protocol')

def opush_test(bdaddr):
    try:
        self_port = search_port(bdaddr=bdaddr, types='opush')
        print(Fore.GREEN + f'OPUSH:{self_port}  Connect Success' + Fore.RESET)
    except Exception:
        print(Fore.RED + 'No OPUSH Protocol')


if sys.argv[1] == 'SDP':
    sdp_test(sdp_psm, sdp_pkt)
elif sys.argv[1] == 'RFCOMM':
    rfcomm_test(rfcomm_psm, rfcomm_pkt)
elif sys.argv[1] == 'BNEP':
    bnep_test(bnep_psm, bnep_pkt)
elif sys.argv[1] == 'AVRCP':
    avrcp_test(avrcp_psm, avrcp_pkt)
elif sys.argv[1] == 'AVDTP':
    avdtp_test(avdtp_psm, avdtp_pkt)

elif sys.argv[1] == '':
    pan_test(bnep_psm,)



elif sys.argv[1] == 'PBAP':
    pbap_test(bdaddr)
elif sys.argv[1] == 'MAP':
    map_test(bdaddr)
elif sys.argv[1] == 'FTP':
    ftp_test(bdaddr)
elif sys.argv[1] == 'OPUSH':
    opush_test(bdaddr)

