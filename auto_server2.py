import socket
import binascii
import atexit
import time
import struct
import random
import os.path

DEBUG_MODE = True

SERVER_PORT = 10029
SERVER_ID = 0x1337

special_keys = {
    "SERVER_ID" : SERVER_ID,
    "SERVER_PORT" : SERVER_PORT,
    "CLIENT_IP" : struct.unpack("<L", socket.inet_aton("192.168.0.86"))[0]
}

PACKET_PREAMBULE = [b'\xC3\x81', b'\xC4\x81']
TYPE_DISCOVER = 0x19
TYPE_GAME_INFO = 0x1A

def terminate():
    server.close()
atexit.register(terminate)

def pad(data, size):
    return data + (b'\x00' * (size - len(data)))

def save_data(data, prefix="client"):
    i = 0
    while os.path.exists("debug/" + prefix + str(i) + ".bin"):
        i += 1
    f = open("debug/" + prefix + str(i) + ".bin", "wb+")
    f.write(data)
    f.close()

def handle_packet(data, addr):
    sz = struct.unpack("<H", data[2:4])[0]
    sz_ = data[2]
    payload = data[4:]
    if (len(payload) != sz and len(payload) - 2 != sz_):
        print("# WARNING: INCOMPLETE PAYLOAD")

    if (data[0:2] in PACKET_PREAMBULE):
        if data[0:2] == PACKET_PREAMBULE[0]:
            handle_payload_t1(payload, addr)
        elif data[0:2] == PACKET_PREAMBULE[1]:
            handle_payload_t2(payload, addr)
    else:
        handle_packet_short(data, addr)

def handle_payload_t1(payload, addr):
    sz = struct.unpack(">H", payload[2:4])[0]
    type = payload[1]
    if len(payload[2:]) != sz:
        print("# WARNING: UNMATCHING PAYLOAD SIZE")
    if type == TYPE_DISCOVER:
        send_game_info(payload[4:], addr)

def handle_payload_t2(payload, addr):
    dest_id = struct.unpack("<H", payload[0:2])[0]
    src_id = struct.unpack("<H", payload[9:11])[0]
    is_resp = (struct.unpack("<H", payload[2:4])[0] == 0x1)

    if dest_id == SERVER_ID:
        if not is_resp: # client is requesting for id confirmation
            send_machine_auth_confirm(addr, src_id, is_resp=True)
            send_machine_auth_confirm(addr, src_id, is_resp=False) # send back auth request
        else:
            pass # we don't care about client's identity

def handle_packet_short(data, addr):
    head, unk = data[0:2], struct.unpack("<H", data[4:6])[0]
    type = data[3]
    #payload = data[4:]
    #dst_id = struct.unpack("<H", payload[8:10])[0]
    #if dst_id == SERVER_ID:
    if type == 0x50:
        send_unk1_short(data, addr)
    else:
        send_short_empty(head, addr)

def make_packet_t1(payloads, args):
    payload = b''
    n = 1
    type = int(args[0].split(" ")[0], 16)
    for entry in payloads:
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

def make_packet_t2(payloads, args):
    payload = payloads[0]
    dest_id = args[1]
    is_resp = args[2]

    payload_header = struct.pack("<H", dest_id)
    payload_header += struct.pack("<H", (0x1 if is_resp else 0x0))

    packet_header = PACKET_PREAMBULE[1]
    packet_header += struct.pack("<H", len(payload_header) + len(payload))

    return packet_header + payload_header + payload

def make_packet_short(payloads, args):
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

def make_packet_from_template(template, args):
    f = open(template, "r")
    buf = f.read()
    f.close()

    template = buf.split("\n")[0].split("#")[0]
    packet_id, packet_args = template.split(":")
    args += packet_args.split(",")

    make_packet = None
    if packet_id == "T1":
        make_packet = make_packet_t1
    elif packet_id == "T2":
        make_packet = make_packet_t2
    elif packet_id == "S0":
        make_packet = make_packet_short

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
            elif "%" in line:
                d = special_keys.get(line.split("%")[1])
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

    return make_packet(payloads, args)

def send_packet(packet, addr):
    if DEBUG_MODE:
        print("Sending packet to " + addr[0] + ":" + str(addr[1]))
    save_data(packet, prefix="server")
    server.sendto(packet, addr)

def send_game_info(payload, addr):
    #entries = extract_payloads(payload)
    args = []
    packet = make_packet_from_template("game_info.wht", args)
    send_packet(packet, addr)

def send_machine_auth_confirm(addr, dst_id, is_resp):
    args = [addr, dst_id, is_resp]
    packet = make_packet_from_template("auth_confirm.wht", args)
    send_packet(packet, addr)

def send_unk1_short(packet, addr):
    resp = packet[0:4]
    resp += struct.pack("<H", random.getrandbits(16)) # Anything
    resp += struct.pack("<H", 0x0)
    resp += packet[8:12]
    resp += struct.pack("<H", SERVER_ID)
    resp += struct.pack("B", random.getrandbits(8)) # Anything
    resp += packet[15:18]
    send_packet(resp, addr)

def send_short_empty(head, addr):
    data = head + struct.pack("<L", 0x0)
    send_packet(data, addr)

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
    if addr[0] == LOCAL_IP:
        continue
    if DEBUG_MODE:
        print("Received packet from " + str(addr))
        save_data(data)
    handle_packet(data, addr)

server.close()
