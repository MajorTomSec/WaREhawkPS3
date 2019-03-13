import socket
import binascii
import atexit
import time
import struct
import os.path

DEBUG_MODE = True

SERVER_PORT = 10029
SERVER_ID = 0x1337

PACKET_PREAMBULE = [b'\xC3\x81', b'\xC4\x81']
TYPE_DISCOVER = 0x19
TYPE_GAME_INFO = 0x1A

def terminate():
    server.close()
atexit.register(terminate)

def pad(data, size):
    return data + (b'\x00' * (size - len(data)))

def save_data(data):
    i = 0
    while os.path.exists("debug/debug" + str(i) + ".bin"):
        i += 1
    f = open("debug/debug" + str(i) + ".bin", "wb+")
    f.write(data)
    f.close()

def handle_payload(payload):
    sz = struct.unpack(">H", payload[2:4])[0]
    type = payload[1]
    if len(payload[2:]) != sz:
        print("# WARNING: UNMATCHING PAYLOAD SIZE")
        # return
    if type == TYPE_DISCOVER:
        send_game_info(payload[4:])
    elif type == TYPE_GAME_INFO:
        pass

def make_packet_t1(paylods, args):
    payload = b''
    n = 1
    type = int(args[0].split(" ")[0], 16)
    for entry in paylods:
        header = b''
        header += bytes([n])
        header += b'\x80'
        header += struct.pack("<H", len(entry))
        payload += header + entry
        n += 1
    payload_header = b'\x00'
    payload_header += bytes([type])
    payload_header += struct.pack(">H", len(payload) + 2)

    packet_header = PACKET_PREAMBULE[0]
    packet_header += struct.pack("<H", len(payload_header) + len(payload))

    return packet_header + payload_header + payload

def make_packet_t2(paylods, args):
    return None

def extract_payloads(payload):
    subs = []
    parsed = 0
    while parsed < len(payload):
        head = payload[parsed:parsed+4]
        sub_size = struct.unpack("<H", head[2:4])[0]
        subs.append(payload[parsed+4:parsed+4+sub_size])
        parsed += sub_size + len(head)
    return subs

def find_attr(payload, attr, size):
    for i in range(0, len(payload), 4):
        if struct.unpack("<L", payload[i:i+4])[0] == attr:
            return payload[i+4:i+4+size]
    return None

def extract_ip_port(from_payload):
    val = find_attr(from_payload, 0x6, 10) # ip + 0*4 + port
    ip = socket.inet_ntoa(val[0:4])
    port = struct.unpack("<H", val[8:10])[0]
    return (ip, port)

def make_packet_from_template(template):
    f = open(template, "r")
    buf = f.read()
    f.close()

    template = buf.split("\n")[0].split("#")[0]
    packet_id, args = template.split(":")
    packet_args = args.split(",")

    make_packet = None
    if packet_id == "T1":
        make_packet = make_packet_t1
    else:
        make_packet = make_packet_t2

    payloads = []
    data = b''
    for line in buf.split("\n")[1:]:
        line = line.split('#')[0]
        if len(line) == 0:
            continue
        if "=>" in line and len(data) > 0:
            payloads.append(data)
            data = b''
            continue
        elif "=>" in line:
            continue

        if "%SERVER_IP%" in line:
            data += socket.inet_aton(LOCAL_IP)
        elif "%SERVER_PORT%" in line:
            data += struct.pack("<H", SERVER_PORT)
        elif "%SERVER_ID%" in line:
            data += struct.pack("<H", SERVER_ID)
        else:
            padding = 4
            is_str = False
            if ":" in line:
                padding = int(line.split(":")[1])
                line = line.split(":")[0]
            if line.startswith('"'):
                d = bytes(line.split('"')[1], 'utf-8')
                is_str = True
            else:
                line = line.split(" ")[0]
                if line.startswith("0x"):
                    d = int(line, 16)
                else:
                    d = int(line)

            if not is_str:
                if padding == 1:
                    data += struct.pack("B", d)
                elif padding == 2:
                    data += struct.pack("<H", d)
                elif padding == 4:
                    data += struct.pack("<L", d)
                elif padding == 8:
                    data += struct.pack("<Q", d)
            else:
                data += pad(d, padding)

    if len(data) > 0:
        payloads.append(data)

    if make_packet == None:
        print("# ERROR: INVALID TEMPLATE !")
        return None

    return make_packet(payloads, packet_args)

def send_game_info(payload):
    entries = extract_payloads(payload)
    to_addr = extract_ip_port(entries[0])
    if DEBUG_MODE:
        print("Sending game_info to " + to_addr[0] + ":" + str(to_addr[1]))
    packet = make_packet_from_template("game_info.wht")
    save_data(packet)
    server.sendto(packet, ("<broadcast>", SERVER_PORT))

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

LOCAL_IP = get_ip()

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
server.bind(('', SERVER_PORT))
print("Started server on " + LOCAL_IP + ":" + str(SERVER_PORT))

while True:
    data, addr = server.recvfrom(1024)
    if (data[0:2] in PACKET_PREAMBULE):
        if addr[0] == LOCAL_IP:
            continue
        if DEBUG_MODE:
            print("Received packet from " + str(addr))
            save_data(data)
        sz = struct.unpack("<H", data[2:4])[0]
        payload = data[4:]
        if (len(payload) != sz):
            print("# WARNING: INCOMPLETE PAYLOAD")
        handle_payload(payload)

server.close()