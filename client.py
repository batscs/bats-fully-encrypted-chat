from _thread import *
import socket
import hashlib
import rsa
# pip install pycrypto
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
 
# ******************************************************************************
 
# msg as string
# returns bytes-tuple (encrypted_message, aes_nonce)
def encrypt(message):
    aes_cipher = AES.new(aes_key, AES.MODE_GCM)
    return (aes_cipher.encrypt(message.encode()), aes_cipher.nonce)
 
# msg as bytes
# nonce as bytes
# returns bytes
def decrypt(msg, nonce):
    aes_decipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return aes_decipher.decrypt(msg)
 
# msg as string
# returns bytes
def sign(msg):
    return rsa.sign(msg.encode(), privkey, "SHA-256")
 
# msg as string
# returns string
def hash(msg):
    return hashlib.sha224(msg.encode()).hexdigest()
 
# thread-function for continously receiving messages
def chatListener(other):
    while True:
        try:
            packet = other.recv(5120)
 
            nonce = packet[:16]
            signature = packet[16:272]
            msg = packet[272:]
 
            msg = decrypt(msg, nonce)
 
            try:
                rsa.verify(msg, signature, otherkey)
            except:
                print("[CRITICAL WARNING] THE MESSAGE SIGNATURE DOES NOT MATCH UP, THE MESSAGE HAS BEEN COMPROMISED")
 
            print(f"peer: {msg.decode()}")
        except Exception as exc:
            #print(exc)
            other.close()
            print("[INFO] Connection has been closed")
            exit()
 
 
# ******************************************************************************
 
server = socket.socket() 
 
destination = input("Peer IP (empty for localhost): ")
 
if destination == "":
    destination = "127.0.0.1"
 
port = 8766
hosting = False
 
print("------------- ESTABLISHING CONNECTION ------------")
 
print("Generating one-time asymmetric RSA-Keys...")
pubkey, privkey = rsa.newkeys(2048)
print(f"Public Key: {hash(str(pubkey))}")
 
# try to connect to already existing peer_server, otherwise become server
try:
    print(f"Trying to connect with {destination}:{port}")
    server.connect((destination, 8766))
    print(f"Connected to {destination}:{port}")
    other = server
except ConnectionRefusedError:
    hosting = True
 
    print("Could not connect to other peer, trying to become server")
    server = socket.socket()
    # 0.0.0.0 = mask for listening to all available IPv4 Addresses
    server.bind(("0.0.0.0", 8766)) 
    server.listen(1)
    print("Hosting server at: 0.0.0.0:8766")
 
    print("Waiting for other peer to connect...")
    (other, (ip, port)) = server.accept()
 
    print(f"Connection from {ip}:{port}")
 
 
print("------------- SECURING CONNECTION ----------------")
 
print("Transmitting own RSA-Public-Key to peer")
other.send(f"{pubkey}".encode())
 
print("Waiting for other peers' RSA-Public-Key...")
otherkey_string = other.recv(10000).decode()
 
# Other Public Key zu einem rsa.PublicKey Objekti zusamensetzen
split_string = otherkey_string.split('(')[1].split(')')[0].split(', ')
modulus = int(split_string[0])
exponent = int(split_string[1])
# Erstellen des PublicKey-Objekts
otherkey = rsa.PublicKey(modulus, exponent)
print(f"Received others' public key: {hash(str(otherkey))}")
 
# Ensure verifyhashsum is calculated in the same order, host key first
if hosting:
    verifyhashsum = hash(f"{pubkey}{otherkey}")
else:
    verifyhashsum = hash(f"{otherkey}{pubkey}")
 
# Clients should compare this themselves, ensures PublicKey Correctness
print(f"Verifcation RSA-Checksum: {verifyhashsum}")
 
print("(Optional) Verify that this is indeed the public key over a different communication-channel")
 
# Verify & Compare (automatically) RSA-Checksum with other peer (not bullet-proof)
other.send(verifyhashsum.encode())
othersum = other.recv(2048).decode()
 
# if equals, could still be tampered with, cant be automatically compared if man in the middle
if othersum != verifyhashsum:
    print("[CRITICAL WARNING] VERIFICATION HASH SUM OF PUBLIC KEYS DOES NOT MATCH - CONNECTION INSECURE")
 
# AES Encryption required, because RSA has only a very limited amount of bytes it can encrypt, not good
if hosting:
    key_length = 32
    aes_key = get_random_bytes(key_length)
    print("Generated AES Key")
    other.send(rsa.encrypt(aes_key, otherkey))
    print("Transmitted AES Key to Peer, communication can begin now")
else:
    msg = other.recv(2048)
    aes_key = rsa.decrypt(msg, privkey)
    print("Received AES Key from Peer, communication can begin now.")
 
print("------------- CONNECTION ESTABLISHED -------------")
 
# Listen on a new Thread to incoming chat messages from other peer
start_new_thread(chatListener, (other,))
 
# Listen here for new input() from this session to send to other peer
while True:
    try:
        message = input("")
 
        if message == "/q":
            other.close()
            print("[INFO] Quitting...")
            exit()
 
        signature = sign(message)
        
        (message_encrypted, nonce) = encrypt(message)
        
        # 16 byte nonce, (sha)256 byte signature, rest=message
 
        packet = nonce + signature + message_encrypted
        other.sendall(packet)  
 
    except KeyboardInterrupt:
        print("[INFO] Quitting (KeyboardInterrupt)...")
        exit()
    except Exception as error:
        print("[INFO] Quiting (Connectiong lost)...")
        exit()