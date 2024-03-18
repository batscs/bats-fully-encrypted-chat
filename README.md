# Encrypted Peer2Peer Chat

![example](https://git.bats.li/bats/peer2peer-e2ee-chat/raw/branch/main/doc/chat.png/chat.png)

This python project demonstrates a securely encrypted implementation for a peer2peer chat with an RSA Key Exchange and AES-256 Encrypted Messages. This works locally between two instances of this script, to work online make sure you have forwarded the port 8766 on both ends.
 
The critical phase of this demonstration is while connecting the two peers with each other and exchanging the keys. The most dangerous attack would be a Man-In-The-Middle replacing the Public-Keys. Protection against this comes in two layers. 
1. The first one being a client-sided Verification-Checksum of both Public-Keys combined. As this happens automatically, always at the same step, this too could be compromised by a MITM.
2. The second layer, being the stronger one, utilizes the RSA-Signature utility. This calculate the checksum of the unencrypted message, and encrypts it with the Senders Private-Key. The Receiver can now verify that the message has not been compromised, given that the Public-Key-Exchange as described in the first step was secure.
 
It is important to note that it is not possible to protect against a Man-In-The-Middle since the beginning, who replaced both Public-Keys with his own Public-Keys.   
 
## Requirements:
- python3
- python3-rsa 
- pycryptodome

## How it works
### Connecting
#### Establishing Connection between two peers
1. Connect to server of other peer, if connection failed, instead become the server and let the other peer connect to own server  
2. Exchange RSA-Public Keys & Verify integrity
3. Peer hosting the Server will create a AES-Key and share it securely, encrypted E2E with RSA
 
### Metadata & Message
#### Each Packet is seperated into three segments
1. (16-bytes) AES-Nonce: AES-Decryption requires the nonce from the Encryption. This is provided as header information and is not sensitive data.
2. (256-bytes) RSA-Signature: Checksum (sha256) of the unencrypted message, result is encrypted with the RSA-Private-Key of the sender. The receiving peer can encrypt this data with the Public-Key of the Peer and verify the checksum against the decrypted third segment, the sensitive message. Protects against Man-in-the-Middle attacks, providing malicious PublicKeys to each peer while connecting.
3. (Trailing bytes) Encrypted Message: The AES-Encrypted message, can be decrypted with the AES-Nonce and the at the beginning securely exchanged AES-Key. 