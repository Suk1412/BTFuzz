#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import socket
import bluetooth

address = '22:22:D0:94:43:00'
# 定义目标设备的MAC地址和端口号
target_address = '22:22:D0:94:43:00'
port = 1

# 尝试连接
sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
try:
    sock.connect((target_address, port))
except bluetooth.btcommon.BluetoothError as err:
    print('Connection error: ', err)
    sock.close()
    # 处理连接错误

# 发送数据
sock.send('Hello, world!')

# 接收数据
data = sock.recv(1024)
print('Received:', data)

# 关闭连接
sock.close()