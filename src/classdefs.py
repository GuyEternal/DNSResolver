from dataclasses import dataclass
from enum import Enum

class QR(Enum):
    QUERY = 0
    RESPONSE = 1

class OPCODE(Enum):
    QUERY = 0
    IQUERY = 1
    STATUS = 2

class AA(Enum):
    NON_AUTHORITY = 0
    AUTHORITY = 1

class TC(Enum):
    NON_TRUNCATED = 0
    TRUNCATED = 1

class RD(Enum):
    RECURSION_NOT_DESIRED = 0
    RECURSION_DESIRED = 1

class RA(Enum):
    RECURSION_NOT_AVAILABLE = 0
    RECURSION_AVAILABLE = 1

class Z(Enum):
    RESERVED = 0
    
class RCODE(Enum):
    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5
    # other values are reserved

class Type(Enum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28

class Class(Enum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4

@dataclass
class Header:
    id: int
    flags: int
    QDCOUNT: int
    ANCOUNT: int
    NSCOUNT: int
    ARCOUNT: int
    def get_rcode(self):
        return self.flags & 0x000F

@dataclass
class Question:
    QNAME: str
    QTYPE: Type
    QCLASS: Class
    
@dataclass
class ResourceRecord:
    NAME: str
    TYPE: Type
    CLASS: Class
    TTL: int
    RDLENGTH: int
    RDATA: str

@dataclass
class Message:
    _Header: Header
    _Question: Question
    _Answer: list[ResourceRecord]
    _Authority: list[ResourceRecord]
    _Additional: list[ResourceRecord]


