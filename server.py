import socket
import binascii
import atexit
import time

UDP_IP = "192.168.56.1"
UDP_PORT = 10029

def terminate():
    server.close()

def hexdump(data):
    f = open("client.bin", "wb+")
    f.write(data)
    f.close()

atexit.register(terminate)

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
server.bind(("192.168.56.1", UDP_PORT))

data, addr = server.recvfrom(1024)
print("received message from : " + str(addr))

# TODO : switch case compare data
f = open("server.bin", "rb")
data = f.read()
f.close()

server.sendto(data, ('<broadcast>', UDP_PORT))
print("message sent!")

data, addr = server.recvfrom(1024)
data, addr = server.recvfrom(1024)
print("received message from : " + str(addr))
print(binascii.hexlify(data))
hexdump(data)

server.close()
