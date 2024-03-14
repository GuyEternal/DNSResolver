from dataclasses import dataclass

@dataclass
class Header:
    id: int
    flags: int
    QDCOUNT: int
    ANCOUNT: int
    NSCOUNT: int
    ARCOUNT: int

@dataclass
class Question:
    QNAME: str
    QTYPE: int
    QCLASS: int
    
@dataclass
class ResourceRecord:
	NAME: str
	TYPE: int
	CLASS: int
	TTL: int
	RDLENGTH: int
	RDATA: str

@dataclass
class Answer:
	 RRs: list[ResourceRecord]
@dataclass
class Authority:
	 RRs: list[ResourceRecord]
@dataclass
class Additional:
	 RRs: list[ResourceRecord]  

@dataclass
class Message:
    _Header: Header
    _Question: Question
    _Answer: Answer
    _Authority: Authority
    _Additional: Additional