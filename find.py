#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from random import randrange

import bluetooth

# bt_addr = '3C:28:6D:29:5A:A0'
# services = bluetooth.find_service(address=bt_addr)
# print(services)


psm4fuzz = randrange(0x0D00, 0x0DFF + 0x0001)
print(psm4fuzz)
