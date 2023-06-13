#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import bluetooth
from colorama import Fore

protocol_uuid_dict = {
    'A2DP': '110D',
    'ATT': '0007',
    'AVRCP': '110E',
    'BNEP': '000f',
    'FTP': '1106',
    'HFP': '111E',
    'HID': '1812',
    'HSP': '1108',
    'L2CAP': '0100',
    'MAP': '1134',
    'OBEX': '0008',
    'OPP': '1105',
    'PAN': '1115',
    'PBAP': '1130',
    'RFCOMM': '0003',
    'SPP': '1101',
}

class Protocol_Exists():
    def __init__(self, *args, **kwargs):
        self.service_port = {}

    def service_check(self, target='22:22:C5:21:D5:B3', uuid='0100'):
        uuid_128 = f'0000{uuid}-0000-1000-8000-00805F9B34FB'
        services = bluetooth.find_service(address=target, uuid=uuid_128)
        if services:
            service_name = [k for k, v in protocol_uuid_dict.items() if v == uuid][0]
            if service_name in ['L2CAP', 'RFCOMM', 'OBEX']:
                self.service_port[service_name] = '1'
            else:
                for service in services:
                    if service['protocol'] == 'L2CAP':
                        self.service_port[service_name] = service['port']
                    if service['protocol'] == 'RFCOMM':
                        self.service_port[service_name] = service['port']

        else:
            service_name = [k for k, v in protocol_uuid_dict.items() if v == uuid][0]
            self.service_port[service_name] = None

    def protocol_exist(self, target='22:22:C5:21:D5:B3'):
        uuid_list = list(protocol_uuid_dict.values())
        for uuid_16 in uuid_list:
            self.service_check(target, uuid_16)
        return self.service_port


# xiaomi = '74:23:44:22:4c:5b'
# testing = '22:22:15:8a:65:4a'
# xyy = "f9:c1:63:d5:8f:00"
# IQOOtest = '22:22:c5:21:d5:b3'
# HUAWEItest = '14:A3:2F:C5:3B:63'
#
# Prol = Protocol_Exists()
# li = Prol.protocol_exist(target=HUAWEItest)
# print(li)


