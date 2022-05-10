# Ofir Shtrosberg, Itamar Laredo
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import socket
import sys
from datetime import datetime

# initialize args
password = bytes(sys.argv[1], encoding='utf-8')
salt = bytes(sys.argv[2], encoding='utf-8')
port = int(sys.argv[3])

# create tcp socket
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.bind(("", int(port)))
socket.listen()

# load symmetric key
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000, )

key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)

while True:
    # wait for client and print received data with time step
    conn, addr = socket.accept()
    data = conn.recv(8192)
    recv = f.decrypt(data).decode('utf-8')
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    print(recv + " " + current_time)
