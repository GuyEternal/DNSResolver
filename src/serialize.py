import struct
import socket
# Serialize the message
# Encode
def encode_qname(qname):
    labels = qname.split('.')
    qname = b''
    for label in labels:
        length = struct.pack('!B', len(label))
        qname += length + label.encode()
    qname += b'\x00'
    return qname

def serialize_header(header):
    id = header.id.to_bytes(2, byteorder='big')
    flags = header.flags.to_bytes(2, byteorder='big')
    QDCOUNT = header.QDCOUNT.to_bytes(2, byteorder='big')
    ANCOUNT = header.ANCOUNT.to_bytes(2, byteorder='big')
    NSCOUNT = header.NSCOUNT.to_bytes(2, byteorder='big')
    ARCOUNT = header.ARCOUNT.to_bytes(2, byteorder='big')
    return id + flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

def serialize_question(question):
    qname = encode_qname(question.QNAME)
    qtype = question.QTYPE.value.to_bytes(2, byteorder='big')
    qclass = question.QCLASS.value.to_bytes(2, byteorder='big')
    q = qname + qtype + qclass
    return q

def serialize_query_message(message):
    header = serialize_header(message._Header)
    question = serialize_question(message._Question)
    return header + question

# Send a UDP Datagram to the DNS server
def send_udp_message(message, address, port):
	
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		sock.sendto(message, (address, port))
		data, _ = sock.recvfrom(1024) # Get the first 1024 bytes of the response. If the response is larger than 1024 bytes, we will have to send another request to get the rest of the response
	return data
