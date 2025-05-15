import coin_messages_pb2
import hashlib
import socket
import struct
import sys

def send_message(sock, message):
    print(f"Sending request: {message}")
    data = message.SerializeToString()
    length_prefix = struct.pack('>I', len(data)) # 4 bytes, big endian
    sock.sendall(length_prefix + data)

def receive_message(sock, message_type):
    # Read 4 bytes for the length
    length_data = sock.recv(4)
    if not length_data:
        return None
    length = struct.unpack('>I', length_data)[0]

    # Read the actual message
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        data += chunk

    message = message_type()
    message.ParseFromString(data)
    print(f"Received response: {message}")
    return message

def mine(data_block, difficulty_mask, nonce_start, nonce_end):

    for nonce in range(nonce_start, nonce_end):
        buf = f"{data_block}{nonce}".encode('utf-8')
        sha1 = hashlib.sha1()
        sha1.update(buf)
        digest = sha1.digest()

        # Get the first 32 bits
        hash_front = int.from_bytes(digest[:4], 'big')

        if (hash_front & difficulty_mask) == hash_front:
            return nonce, digest

    return None, None

if len(sys.argv) < 3:
    print(f'Usage: {sys.argv[0]} hostname port')
    sys.exit(1)

sock = socket.create_connection((sys.argv[1], int(sys.argv[2])))

try:
    envelope = coin_messages_pb2.Envelope()
    envelope.registration_request.username = "Matthew"
    send_message(sock, envelope)

    resp = receive_message(sock, coin_messages_pb2.Envelope)

    envelope = coin_messages_pb2.Envelope()
    req = coin_messages_pb2.TaskRequest()
    envelope.task_request.CopyFrom(req)
    send_message(sock, envelope)

    resp = receive_message(sock, coin_messages_pb2.Envelope)

    nonce, digest = mine( \
                         resp.task_reply.block, \
                         resp.task_reply.difficulty_mask, 1, 2**64 - 1)

    envelope = coin_messages_pb2.Envelope()
    envelope.verification_request.block = resp.task_reply.block
    envelope.verification_request.difficulty_mask = resp.task_reply.difficulty_mask
    envelope.verification_request.nonce = nonce
    envelope.verification_request.sequence_num = resp.task_reply.sequence_num
    send_message(sock, envelope)

    resp = receive_message(sock, coin_messages_pb2.Envelope)

    if resp.verification_reply.ok == True:
        print('We did it!')
finally:
    sock.close()
