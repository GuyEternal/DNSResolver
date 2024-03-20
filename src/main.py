from classdefs import *
from serialize import *
from sys import getsizeof

def main():
    msg = Message(
        Header(
            id=0x8298, # As long as we're sending only one request it can be any value, only if we are sending multiple requests we need to keep track of the id so that we can match the response with the request
            flags= QR.QUERY.value<<15 | OPCODE.QUERY.value<<11 | RD.RECURSION_DESIRED.value<<8, # We take or of the values to set the flags as 100 | 001 => 101 so we can use the enum values directly and take or of them to set the flags 
            QDCOUNT=1, 
            ANCOUNT=0, 
            NSCOUNT=0, 
            ARCOUNT=0),
        Question(
            QNAME='superuser.com',
            QTYPE=Type.AAAA,
            QCLASS=Class.IN),
        None, # No Answer field in query
        None, # No Authority field in query
        None # No Additional field in query
    )
    byte_string_to_send = serialize_query_message(msg)
    response = send_udp_message(byte_string_to_send, '8.8.8.8', 53)
    print(getsizeof(response))
    print(response)

if __name__ == '__main__':
    main()