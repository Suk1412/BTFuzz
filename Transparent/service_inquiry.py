#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import bluetooth

class Protocol_Monitor():
    def __init__(self, target='22:22:C5:21:D5:B3', *args, **kwargs):
        self.target = target
        self.service_port = {}
        self.exists_service = []
        self.protocol_uuid_dict = {
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
        self.protocol_exist()

    def service_scan(self):
        services = bluetooth.find_service(address=self.target)
        for ser in services:
            print(ser)

    def service_check(self, uuid='0100'):
        uuid_128 = f'0000{uuid}-0000-1000-8000-00805F9B34FB'
        services = bluetooth.find_service(address=self.target, uuid=uuid_128)
        if services:
            service_name = [k for k, v in self.protocol_uuid_dict.items() if v == uuid][0]
            if service_name in ['L2CAP', 'RFCOMM', 'OBEX']:
                self.exists_service.append(service_name)
            else:
                for service in services:
                    if service['protocol'] == 'L2CAP':
                        self.service_port[service_name] = service['port']
                        self.exists_service.append(service_name)
                    if service['protocol'] == 'RFCOMM':
                        self.service_port[service_name] = service['port']
                        self.exists_service.append(service_name)
            self.exists_service = list(set(self.exists_service))
            self.exists_service.sort()
        else:
            service_name = [k for k, v in self.protocol_uuid_dict.items() if v == uuid][0]
            self.service_port[service_name] = None

    def protocol_exist(self):
        uuid_list = list(self.protocol_uuid_dict.values())
        for uuid_16 in uuid_list:
            self.service_check(uuid_16)
        return self.service_port


# xiaomi = '74:23:44:22:4c:5b'
# testing = '22:22:15:8a:65:4a'
# xyy = "f9:c1:63:d5:8f:00"
HUAWEItest = '14:A3:2F:C5:3B:63'
# Cartest = '00:87:61:10:55:28'
# IQOOtest2 = '22:22:15:8a:65:4a'
foo = '74:74:46:CD:7E:50'

IQOOtest = '22:22:c5:21:d5:b3'
Prol = Protocol_Monitor(target=HUAWEItest)
print(Prol.service_port)
# print(Prol.exists_service)

# Prol.service_scan()