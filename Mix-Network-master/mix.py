# Ofir Shtrosberg, Itamar Laredo
import threading
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import socket
import sys
import time


# send data function for thread execute
def t_send(ip, port, packet):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip, int(port)))
    client.send(packet)
    client.close()

# manage the received msg's for every round.
# send the msg's randomly
def sendMsgs():
    secure_random = random.SystemRandom()
    while len(recv_msgs) > 0:
        msg_to_send = secure_random.choice(recv_msgs)
        dest_ip = msg_to_send[:4]
        dest_port = msg_to_send[4:6]
        decimal_port = int.from_bytes(dest_port, byteorder=sys.byteorder)
        str_ip = str(dest_ip[0]) + "." + str(dest_ip[1]) + "." + str(dest_ip[2]) + "." + str(dest_ip[3])
        packet = msg_to_send[6:]

        thread = threading.Thread(target=t_send, args=(str_ip, decimal_port, packet,))
        thread.start()
        thread.join()
        recv_msgs.remove(msg_to_send)


# load given secret key
y = sys.argv[1]
file_path = "sk" + str(y) + ".pem"
private_key = ""
with open(file_path, "r") as keyfile:
    for line in keyfile:
        private_key += line

# load next destinations
f = open("ips.txt")
lines = f.readlines()
address = lines[int(y) - 1]
# split ip and port
ip = address.split()[0]
port = address.split()[1]

# create tcp socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("", int(port)))
server.listen()
server.setblocking(False)

recv_msgs = []
end_round = time.time() + 60

# wait for clients with non-blocking the loop.
# every one minute round finish and send the data to the next destinations.
while True:
    if time.time() > end_round:
        sendMsgs()
        recv_msgs.clear()
        end_round = time.time() + 60

    try:
        conn, addr = server.accept()
        data = conn.recv(1024 * pow(2, int(y)))
    except:
        continue

    # load secret key
    with open(file_path, "rb") as f:
        sk = serialization.load_pem_private_key(f.read(), password=None,
                                                backend=default_backend())
    packet = sk.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    recv_msgs.append(packet)
