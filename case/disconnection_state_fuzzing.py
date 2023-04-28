#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from l2cap_state import *

def run(bt_addr):
        print("Start Fuzzing...")
        sock = BluetoothL2CAPSocket(bt_addr)
        state_machine = l2cap_state_machine()
        try:
            disconnection_state_fuzzing(bt_addr, sock, state_machine)
        except Exception as e:
            print(f"[!] Error Message {e}")
        except KeyboardInterrupt as k:
            print(f"[!] Fuzzing Stopped {k}")
