#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import argparse
import sys
import bluetooth
from OuiLookup import OuiLookup
from bluepy.btle import Scanner
from gattlib import DiscoveryService
from l2fuzz import bluetooth_class_of_device, l2cap_fuzzing

from collections import OrderedDict


test_info = OrderedDict()
serv_chosen = OrderedDict()
def bt_scan():
    """
        经典蓝牙扫描
    """
    print('Classic Bluetooth scan...')
    while (True):
        nearby_devices = bluetooth.discover_devices(duration=3, flush_cache=True, lookup_names=True, lookup_class=True)
        i = 1
        print("\tTarget Bluetooth Device List")
        print("\t[No.]\t[BT address]\t\t[Device name]\t\t[Device Class]\t\t[OUI]")
        for addr, name, device_class in nearby_devices:
            device_class = bluetooth_class_of_device(hex(device_class))
            oui = OuiLookup().query(addr)
            print("\t%02d.\t%s\t%s\t\t%s(%s)\t%s" % (i, addr, name, device_class['major'], device_class['minor'], list(oui[0].values())[0]))
            i += 1
        sys.exit()

def le_scan():
    """
        低能耗蓝牙扫描
    """
    print('Low Energy Bluetooth scan...')
    scanner = Scanner()
    devices = scanner.scan(timeout=3)
    print("\tTarget Low Energy Bluetooth Device List")
    for dev in devices:
        print("name: {}\t\t\taddress: {}".format(dev.getValueText(9), dev.addr))


def bluetooth_services_and_protocols_search(bt_addr):
    """
        协议服务扫描
    """
    print("Start scanning services...")
    print("\tList of profiles for the device")
    services = bluetooth.find_service(address=bt_addr)
    if len(services) <= 0:
        print("No services found")
    else:
        i = 0
        print("\t[No]\t[profiles]\t[protocol]\t[port]\t\t[name]")
        for serv in services:
            if len(serv['profiles']) == 0:
                pass
            else:
                print("\t[%02d]\t[0x%s]\t%s\t\t%d\t\t%s" % (i, serv['profiles'][0][0], serv['protocol'], serv['port'], serv['name']))
                i += 1

def fuzz():
    target_addr = "3C:28:6D:29:5A:A0"
    target_profile = "Advanced Audio Source"
    target_profile_port = 25
    l2cap_fuzzing(target_addr, target_profile, target_profile_port, test_info)

def main():
    parser = argparse.ArgumentParser(
        usage='sudo python3 Operation.py -fun scan -mac 3C:28:6D:29:5A:A0 -iface hci0'
    )

    parser.add_argument('-mac',  dest='mac', help='Clients MAC address (fuzzer)')
    parser.add_argument('-iface', dest='iface', help='hciconfig')
    parser.add_argument('-fun', dest='fun', help='执行的操作')

    args = parser.parse_args()

    if not args.fun:
        parser.error('function must be set')
    if args.fun == 'bt_scan':
        bt_scan()
    if args.fun == 'le_scan':
        le_scan()
    if args.fun == 'services_search':
        if not args.mac:
            parser.error('mac must be set')
        else:
            bluetooth_services_and_protocols_search(args.mac)
    if args.fun == 'fuzz':
        fuzz()


if __name__== "__main__":
    main()

