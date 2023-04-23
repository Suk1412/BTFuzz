#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import argparse
import sys
import bluetooth
from OuiLookup import OuiLookup
from bluepy.btle import Scanner

from Bluetooth_Class_of_Device import show_class_of_device
from Bluetooth_Services_And_Protocols_Search import services_and_protocols_search
from l2cap_fuzz import l2cap_fuzzing
from collections import OrderedDict
import re

serv_chosen = OrderedDict()

def bluetooth_class_of_device(device_class):
    # https://github.com/mikeryan/btclassify.git
    class_string = device_class
    m = re.match('(0x)?([0-9A-Fa-f]{6})', class_string)
    if m is None:
        return {"major": "None", "minor": "None", "service": "None"}
    hex_string = m.group(2)
    CoD = int(hex_string, 16)
    classes = ['Miscellaneous', 'Computer', 'Phone', 'LAN/Network Access Point',
               'Audio/Video', 'Peripheral', 'Imaging', 'Wearable', 'Toy', 'Health']
    major_number = (CoD >> 8) & 0x1f
    if major_number < len(classes):
        major = classes[major_number]
    elif major_number == 31:
        major = 'Uncategorized'
    else:
        major = 'Reserved'

    minor_number = (CoD >> 2) & 0x3f
    minor = None

    # computer
    if major_number == 1:
        classes = [
            'Uncategorized', 'Desktop workstation', 'Server-class computer',
            'Laptop', 'Handheld PC/PDA (clamshell)', 'Palm-size PC/PDA',
            'Wearable computer (watch size)', 'Tablet']
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = 'reserved'

    # phone
    elif major_number == 2:
        classes = [
            'Uncategorized', 'Cellular', 'Cordless', 'Smartphone',
            'Wired modem or voice gateway', 'Common ISDN access']
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = 'reserved'

    # network access point
    elif major_number == 3:
        classes = [
            'Fully available', '1% to 17% Utilized', '17% to 33% Utilized',
            '33% to 50% Utilized', '50% to 67% Utilized',
            '67% to 83% Utilized', '83% to 99% Utilized',
            'No service available']
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = 'reserved'

    # audio/video
    elif major_number == 4:
        classes = [
            'Uncategorized', 'Wearable Headset Device', 'Hands-free Device',
            '(Reserved)', 'Microphone', 'Loudspeaker', 'Headphones',
            'Portable Audio', 'Car audio', 'Set-top box', 'HiFi Audio Device',
            'VCR', 'Video Camera', 'Camcorder', 'Video Monitor',
            'Video Display and Loudspeaker', 'Video Conferencing',
            '(Reserved)', 'Gaming/Toy']
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = 'reserved'

    # peripheral, this one's gross
    elif major_number == 5:
        feel_number = minor_number >> 4
        classes = [
            'Not Keyboard / Not Pointing Device', 'Keyboard',
            'Pointing device', 'Combo keyboard/pointing device']
        feel = classes[feel_number]

        classes = [
            'Uncategorized', 'Joystick', 'Gamepad', 'Remote control',
            'Sensing device', 'Digitizer tablet', 'Card Reader', 'Digital Pen',
            'Handheld scanner for bar-codes, RFID, etc.',
            'Handheld gestural input device']
        if minor_number < len(classes):
            minor_low = classes[minor_number]
        else:
            minor_low = 'reserved'

        minor = '%s, %s' % (feel, minor_low)

    # imaging
    elif major_number == 6:
        minors = []
        if minor_number & (1 << 2):
            minors.append('Display')
        if minor_number & (1 << 3):
            minors.append('Camera')
        if minor_number & (1 << 4):
            minors.append('Scanner')
        if minor_number & (1 << 5):
            minors.append('Printer')
        if len(minors) > 0:
            minors = ', '.join(minors)

    # wearable
    elif major_number == 7:
        classes = ['Wristwatch', 'Pager', 'Jacket', 'Helmet', 'Glasses']
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = 'reserved'

    # toy
    elif major_number == 8:
        classes = ['Robot', 'Vehicle', 'Doll / Action figure', 'Controller',
                   'Game']
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = 'reserved'

    # health
    elif major_number == 9:
        classes = [
            'Undefined', 'Blood Pressure Monitor', 'Thermometer',
            'Weighing Scale', 'Glucose Meter', 'Pulse Oximeter',
            'Heart/Pulse Rate Monitor', 'Health Data Display', 'Step Counter',
            'Body Composition Analyzer', 'Peak Flow Monitor',
            'Medication Monitor', 'Knee Prosthesis', 'Ankle Prosthesis',
            'Generic Health Manager', 'Personal Mobility Device']
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = 'reserved'

    services = []
    if CoD & (1 << 23):
        services.append('Information')
    if CoD & (1 << 22):
        services.append('Telephony')
    if CoD & (1 << 21):
        services.append('Audio')
    if CoD & (1 << 20):
        services.append('Object Transfer')
    if CoD & (1 << 19):
        services.append('Capturing')
    if CoD & (1 << 18):
        services.append('Rendering')
    if CoD & (1 << 17):
        services.append('Networking')
    if CoD & (1 << 16):
        services.append('Positioning')
    if CoD & (1 << 15):
        services.append('(reserved)')
    if CoD & (1 << 14):
        services.append('(reserved)')
    if CoD & (1 << 13):
        services.append('Limited Discoverable Mode')

    output = {"major": major, "minor": minor, "service": services}
    return output

def bt_scan():
    """
        经典蓝牙扫描
    """
    print('Classic Bluetooth scan...')
    while (True):
        nearby_devices = bluetooth.discover_devices(duration=3, flush_cache=True, lookup_names=True, lookup_class=True)
        i = 1
        print("\tTarget Bluetooth Device List")
        # print("\t[No.]\t[BT address]\t\t[Device name]\t\t[Device Class]\t\t[OUI]")
        print(f"\t[No.]{' '*(10-len('[No.]'))}"
              f"[BT address]{' '*(25-len('[BT address]'))}"
              f"[Device name]{' '*(30-len('[Device name]'))}"
              f"[Device Class]{' '*(35-len('[Device Class]'))}"
              f"[OUI]")
        for addr, name, device_class in nearby_devices:
            device_class = bluetooth_class_of_device("0x%s" % hex(device_class)[2:].zfill(6))
            oui = OuiLookup().query(addr)
            # print("\t%02d.\t%s\t%s\t\t%s(%s)\t%s" % (i, addr, name, device_class['major'], device_class['minor'], list(oui[0].values())[0]))
            print(f"\t{i}.{' '*(10-len(str(i)+'.'))}"
                  f"{addr}{' '*(25-len(str(addr)))}"
                  f"{name}{' '*(30-len(str(name)))}"
                  f"{device_class['major']}({device_class['minor']}){' '*(35-len(device_class['major'])-len(device_class['minor'])-2)}"
                  f"{list(oui[0].values())[0]}")
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
        print("\t[No.]\t[profiles]\t[protocol]\t[port]\t\t[name]")
        for serv in services:
            if len(serv['profiles']) == 0:
                pass
            else:
                print("\t%02d.\t0x%s\t\t%s\t\t%d\t\t%s" % (i, serv['profiles'][0][0], serv['protocol'], serv['port'], serv['name']))
                i += 1

def main():
    parser = argparse.ArgumentParser(
        usage='sudo python3 Operation.py -fun scan -mac 3C:28:6D:29:5A:A0 -iface hci0'
    )
    parser.add_argument('-mac',  dest='mac', help='Clients MAC address (fuzzer)')
    parser.add_argument('-iface', dest='iface', help='hciconfig')
    parser.add_argument('-fun', dest='fun', help='执行的操作')
    parser.add_argument('-cod', dest='cod', help='CoD值')
    args = parser.parse_args()

    if not args.fun:
        parser.error('function must be set')
    if args.fun == 'bt_scan':
        """经典蓝牙扫描"""
        bt_scan()
    if args.fun == 'le_scan':
        """低能耗蓝牙扫描"""
        le_scan()
    if args.fun == 'search':
        """扫描目标服务"""
        if not args.mac:
            parser.error('sudo python3 Operation.py -fun search -mac 3C:28:6D:29:5A:A0')
        else:
            bluetooth_services_and_protocols_search(args.mac)
    if args.fun == 'check':
        """查看蓝牙CoD对应的设备类型"""
        if not args.cod:
            parser.error('sudo python3 Operportation.py -fun check -cod 0x200404')
        else:
            show_class_of_device(args.cod)
    if args.fun == 'fuzz':
        """对目标设备开启模糊测试"""
        if not args.mac:
            parser.error('sudo python3 Operation.py -fun fuzz -mac 22:22:C5:21:D5:B3')
        if args.mac:
            target_addr = args.mac
            protocol_select = services_and_protocols_search(target_addr)
            target_profile = protocol_select['service']
            target_profile_port = protocol_select['port']
            if protocol_select['protocol'] == 'L2CAP':
                l2cap_fuzzing(target_addr, target_profile, target_profile_port)


if __name__== "__main__":
    main()

