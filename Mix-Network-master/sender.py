# Ofir Shtrosberg, Itamar Laredo
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import socket
import sys
from threading import Thread
from time import sleep


# define packet elements
class Packets:
    def __init__(self, packet, ip, port, msg_round):
        self.packet = packet
        self.ip = ip
        self.port = port
        self.round = msg_round


# sleep until packets round come,
# then initialize tcp socket and send the msg's
def sender_func(round_packets):
    sleep((int(round_packets[0].round) * 60))  # sleep until its round become
    for i in round_packets:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((i.ip, int(i.port)))
        client.send(i.packet)
        client.close()


# Encrypt string with symmetric key
def Enc(k, string):
    return Fernet(k).encrypt(bytes(string, encoding='utf-8'))


# wrapping the packets with ip&port and encrypt the result.
def wrapper(pk, address, packet):
    ip_wrapper = address.split()[0]
    port_wrapper = address.split()[1]
    # convert ip&port to hexa representation
    ip_split = ip_wrapper.split('.')
    hexa_ip = bytes([int(ip_split[0]), int(ip_split[1]), int(ip_split[2]), int(ip_split[3])])
    hexa_port = int(port_wrapper).to_bytes(2, sys.byteorder)
    data = hexa_ip + hexa_port + packet
    wrapped_packet = pk.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return wrapped_packet


x = sys.argv[1]
packets = []
file_name = "messages" + str(x) + ".txt"
# read the data file and initialize fields
with open(file_name, "r") as file:
    for line in file:
        line_split = line.split()
        message = line_split[0]
        path = line_split[1]
        msg_round = line_split[2]
        password = bytes(line_split[3], encoding='utf-8')
        salt = bytes(line_split[4], encoding='utf-8')
        dst_ip = line_split[5]
        dst_port = line_split[6]

        # encrypt message with symmetric key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000, )

        key = base64.urlsafe_b64encode(kdf.derive(password))
        c = Enc(key, message)

        # convert ip&port to hexa representation
        ip_split = dst_ip.split('.')
        hexa_ip = bytes([int(ip_split[0]), int(ip_split[1]), int(ip_split[2]), int(ip_split[3])])
        hexa_port = int(dst_port).to_bytes(2, byteorder=sys.byteorder)

        # concatenate ip port and encrypted message
        msg = hexa_ip + hexa_port + c

        # wrapping the msg with more destinations by repeating the same process
        path_params = path.split(",")
        addresses = []
        PKs = []
        ips_file = open('ips.txt')
        all_lines = ips_file.readlines()

        for i in reversed(path_params):
            file_path = "pk" + i + ".pem"
            with open(file_path, "rb") as f:
                PK = serialization.load_pem_public_key(f.read(), default_backend())
                PKs.append(PK)

        packet = PKs[0].encrypt(
            msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        for i in range(0, len(all_lines)):
            addresses.append(all_lines[i].strip())

        for i in range(1, len(PKs)):
            packet = wrapper(PKs[i], addresses[i - 1], packet)

        destination = addresses[-1]
        dest_ip = destination.split()[0]
        dest_port = destination.split()[1]
        p = Packets(packet, dest_ip, dest_port, msg_round)
        packets.append(p)

# sort the packets list by round of time
packets.sort(key=lambda x: x.round, reverse=False)

# collecting the elements with same round time and create
# for its new thread to execute the packets sending.
i = 0
temp = []
while i < len(packets):
    j = i
    while j < len(packets) and packets[j].round == packets[i].round:
        temp.append(packets[j])
        j += 1
    i = j
    thread = Thread(target=sender_func, args=(temp,))
    thread.start()
    thread.join()
    temp.clear()
