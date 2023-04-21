#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from collections import OrderedDict

import bluetooth


def services_and_protocols_search(bt_addr):
    """
        协议服务扫描
    """
    test_info = OrderedDict()
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
                print("\t%02d.\t%s" % (i, serv['name']))
            else:
                print("\t%02d.\t0x%s\t\t%s\t\t%d\t\t%s" % (i, serv['profiles'][0][0], serv['protocol'], serv['port'], serv['name']))
            i += 1

    while (True):
        user_input = int(input("\nSelect a profile to fuzz : "))
        if user_input < len(services) and user_input > -1:
            idx = user_input
            serv_chosen = services[idx]
            break
        else:
            print("[-] Out of range.")
    print("\n\tProtocol for the profile [%s] : %s\n" % (serv_chosen['name'], serv_chosen['protocol']))

    test_info['protocol'] = serv_chosen['protocol']
    test_info['port'] = serv_chosen['port']
    test_info['service'] = serv_chosen['name']
    print(test_info['service'])
    print(test_info['port'])
    return test_info

