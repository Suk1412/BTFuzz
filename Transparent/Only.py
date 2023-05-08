#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import socket

# 设定远程设备地址和端口号
address = '22:22:D0:94:43:00'
port = 17

# 建立socket连接
sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_L2CAP)
sock.connect((address, port))

# 发送数据
data = b'\x17\x03\x0b\x00'
sock.send(data)

# 接收数据
response = sock.recv(1024)

# 关闭连接
sock.close()