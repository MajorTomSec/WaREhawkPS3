import socket
import binascii
import atexit
import time
import os.path

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

f = open("exchange/discover.bin", "rb")
data = f.read()
f.close()

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
client.settimeout(0.2)
client.bind(("", 44444))

#client.sendto(data, ('<broadcast>', UDP_PORT))
client.sendto(data, ('<broadcast>', UDP_PORT))

n=1
while True:
    data, addr = client.recvfrom(1024)
    print("received message from : " + str(addr))
    save_data(data)
    f = open("client/client" + str(n)  + ".bin", "rb")
    data = f.read()
    f.close()
    client.sendto(data, ('<broadcast>', UDP_PORT))
    print("message sent!")
    n += 1

client.close()
