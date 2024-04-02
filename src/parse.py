from classdefs import *
from serialize import *
import struct


def parse_header(reader):
    items = struct.unpack('!HHHHHH', reader.read(12))
    return Header(*items)

def decode_name_simple(reader):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        parts.append(reader.read(length))
    return b'.'.join(parts)


def parse_question(reader):
    name = decode_name_simple(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack('!HH', data)
    return Question(name, type_, class_)
