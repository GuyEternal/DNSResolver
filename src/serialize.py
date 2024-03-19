import struct
import socket
# Serialize the message

def serialize_query_message(message):
    header = serialize_header(message._Header)
    question = serialize_question(message._Question)
    return header + question

def serialize_header(header):
    id = struct.pack('!H', header.id)
    flags = struct.pack('!H', header.flags)
    QDCOUNT = struct.pack('!H', header.QDCOUNT)
    ANCOUNT = struct.pack('!H', header.ANCOUNT)
    NSCOUNT = struct.pack('!H', header.NSCOUNT)
    ARCOUNT = struct.pack('!H', header.ARCOUNT)
    return id + flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

def serialize_question(question):
    qname = encode_qname(question.QNAME)
    qtype = struct.pack('!H', question.QTYPE.value)
    qclass = struct.pack('!H', question.QCLASS.value)
    return qname + qtype + qclass

def encode_qname(qname):
    labels = qname.split('.')
    qname = b''
    for label in labels:
        length = struct.pack('!B', len(label))
        qname += length + label.encode()
    qname += b'\x00'
    return qname

# Send a UDP Datagram to the DNS server
def send_udp_message(message, address, port):
	
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		sock.sendto(message, (address, port))
		data = sock.recvfrom(1024) # Get the first 1024 bytes of the response. If the response is larger than 1024 bytes, we will have to send another request to get the rest of the response
	return data

# Serialize the message

def serialize_query_message(message):
    header = serialize_header(message._Header)
    question = serialize_question(message._Question)
    return header + question

def serialize_header(header):
    id = struct.pack('!H', header.id)
    flags = struct.pack('!H', header.flags)
    QDCOUNT = struct.pack('!H', header.QDCOUNT)
    ANCOUNT = struct.pack('!H', header.ANCOUNT)
    NSCOUNT = struct.pack('!H', header.NSCOUNT)
    ARCOUNT = struct.pack('!H', header.ARCOUNT)
    return id + flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

def serialize_question(question):
    qname = encode_qname(question.QNAME)
    qtype = struct.pack('!H', question.QTYPE.value)
    qclass = struct.pack('!H', question.QCLASS.value)
    return qname + qtype + qclass

def encode_qname(qname):
    labels = qname.split('.')
    qname = b''
    for label in labels:
        length = struct.pack('!B', len(label))
        qname += length + label.encode()
    qname += b'\x00'
    return qname

# Send a UDP Datagram to the DNS server
def send_udp_message(message, address, port):
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(message, (address, port))
        data, _ = sock.recvfrom(1024)
    return data
