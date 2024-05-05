from classdefs import *
from serialize import *
from sys import getsizeof
from io import BytesIO
from parse import *
from utils import decode_dns_name

def lookup_domain(domain_name, type):
    query = build_query(domain_name, type)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))

    # get the response
    
    data, _ = sock.recvfrom(1024)
    msg_response_obj = parse_dns_packet(data)
    val = ""
    if(len(msg_response_obj._Answer) > 0 and msg_response_obj._Answer[0].TYPE == 5):
        rdata = msg_response_obj._Answer[0].RDATA
        name_bytes = rdata
        print(decode_only_name(name_bytes))
        # lookup_domain(decode_dns_name(name_bytes), Type.A)
    elif(len(msg_response_obj._Answer) > 0):
        ipv4 = [x for x in msg_response_obj._Answer[0].RDATA]
        val = ".".join(map(str, ipv4))
    else:
        val = "!NOT FOUND"
        
    return val

def build_query(domain_name, qtype):
    msg = Message(
        Header(
            id=0x8298, # As long as we're sending only one request it can be any value, only if we are sending multiple requests we need to keep track of the id so that we can match the response with the request
            flags= QR.QUERY.value<<15 | OPCODE.QUERY.value<<11 | RD.RECURSION_DESIRED.value<<8, # We take or of the values to set the flags as 100 | 001 => 101 so we can use the enum values directly and take or of them to set the flags 
            QDCOUNT=1, 
            ANCOUNT=0, 
            NSCOUNT=0, 
            ARCOUNT=0),
        Question(
            QNAME=domain_name,
            QTYPE=qtype,
            QCLASS=Class.IN),
        None, # No Answer field in query
        None, # No Authority field in query
        None # No Additional field in query
    )
    byte_string_to_send = serialize_query_message(msg)
    return byte_string_to_send

def main():
    
    ip = lookup_domain("www.superuser.com", Type.A)
    print(ip)
    

if __name__ == '__main__':
    main()