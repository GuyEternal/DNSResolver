from io import BytesIO
from classdefs import *
from serialize import *
import struct


def parse_header(reader):
    items = struct.unpack('!HHHHHH', reader.read(12))
    return Header(*items)

def parse_question(reader):
    name = decode_name(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack('!HH', data)
    return Question(name, type_, class_)

def decode_only_name(name_bytes):
    parts = []
    i = 0
    while (length := name_bytes[i]) != 0:
        if length & 0b1100_0000:
            pointer_bytes = bytes([length & 0b0011_1111]) + name_bytes[i+1:i+2]
            pointer = struct.unpack("!H", pointer_bytes)[0]
            parts.append(decode_only_name(name_bytes[pointer:]))
            i += 2
            break
        else:
            parts.append(name_bytes[i+1:i+1+length])
            i += 1 + length
        if(len(name_bytes) > i):
            break
    return b".".join(parts).decode()

def decode_name(reader):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)


def decode_compressed_name(length, reader):
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result

def ip_to_string(ip_bytes):
    return ".".join(str(byte) for byte in ip_bytes)

def parse_record(reader):
    name = decode_name(reader)
    data = reader.read(10)
    type_, class_, ttl, data_len = struct.unpack("!HHIH", data)
    if type_ == Type.NS.value:
        data = decode_name(reader)
    elif type_ == Type.A.value:
        data = ip_to_string(reader.read(data_len))
    elif type_ == Type.AAAA.value:
        raw_address = reader.read(16)  # Read 16 bytes for IPv6
        data = ':'.join(format(x, '02x') for x in struct.unpack('!8H', raw_address))
    else:
        data = reader.read(data_len)    
    return ResourceRecord(name, type_, class_, ttl, data_len, data)

def parse_dns_packet(data):
    reader = BytesIO(data)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.QDCOUNT)]
    answers = [parse_record(reader) for _ in range(header.ANCOUNT)]
    authorities = [parse_record(reader) for _ in range(header.NSCOUNT)]
    additionals = [parse_record(reader) for _ in range(header.ARCOUNT)]

    return Message(header, questions, answers, authorities, additionals)