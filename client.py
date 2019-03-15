import socket
import binascii
import atexit
import time
import os.path
import struct

UDP_IP = "192.168.56.1"
UDP_PORT = 10029

def terminate():
    client.close()

def save_data(data):
    i = 0
    while os.path.exists("client/debug" + str(i) + ".bin"):
        i += 1
    f = open("client/debug" + str(i) + ".bin", "wb+")
    f.write(data)
    f.close()

atexit.register(terminate)

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

SERVER_ID = 0
HEAD_ID = 0

def update(data, i):
    if i == 1 or i == 2:
        data = data[0:4] + struct.pack("<H", SERVER_ID) + data[6:]
    if i == 3:
        data = data[0:0xC] + struct.pack("<H", SERVER_ID) + data[0xE:]
    return data

def parse_save(data, i):
    global SERVER_ID
    if i == 1:
        SERVER_ID = struct.unpack("<H", data[0x7A:0x7C])[0]
    save_data(data)

LOCAL_IP = get_ip()

f = open("exchange/discover.bin", "rb")
data = f.read()
f.close()

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#client.settimeout(0.2)
client.bind(("", 44444))

#client.sendto(data, ('<broadcast>', UDP_PORT))
client.sendto(data, ('<broadcast>', UDP_PORT))


n=1
while True:
    data, addr = client.recvfrom(1024)
    if addr[0] == LOCAL_IP:
        continue
    print("received message from : " + str(addr))
    parse_save(data, n)
    f = open("client/client" + str(n)  + ".bin", "rb")
    data = f.read()
    f.close()
    data = update(data, n)
    client.sendto(data, ('<broadcast>', UDP_PORT))
    print("message sent!")
    n += 1

client.close()
