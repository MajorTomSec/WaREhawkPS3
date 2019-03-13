import socket
import binascii
import atexit
import time
import struct

UDP_IP = "192.168.56.1"
UDP_PORT = 10029

def terminate():
    client.close()
atexit.register(terminate)

def type_to_name(type):
    s = "Unknown"
    if (type == 0x1900): # discover
        s = "discover"
    elif (type == 0x1A00):
        s = "game_info"
    return s

def read_file(filename):
    f = open(filename, "rb")
    d = f.read()
    f.close()
    return d

def make_packet(payload):
    packet = b'\xC3\x81' # warhawk packet preambule
    packet += struct.pack("<H", len(payload))
    return packet + payload

def game_info():
    payload = struct.pack("<H", 0x1A00) # type = game_info
    payload += gen_game_metadata(name="Warhawk", max_player=24, game_type='tdm1', map="multi02")
    return payload

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#client.settimeout(0.2)
client.bind(("192.168.56.1", UDP_PORT))

while True:
    data, addr = client.recvfrom(1024)
    if (data[0:2] == b'\xC3\x81'): # Warhawk packet preambule
        sz = struct.unpack("<H", data[2:4])[0]
        payload = data[4:]
        if (len(payload) != sz):
            print("# WARNING: UNMATCHING PAYLOAD SIZE")
            print(sz + " " + len(payload))

        t = struct.unpack("<H", payload[0:2])[0]
        type = type_to_name(t)
        print("[C => S] " + type + " (" + str(t) + ")")

        if (type == "discover"):
            d = read_file("exchange/game_info.bin")
            client.sendto(d, ("<broadcast>", UDP_PORT)) #TODO: change ip

client.close()
