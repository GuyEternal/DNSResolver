import argparse
from classdefs import *
from serialize import *
from sys import getsizeof
from io import BytesIO
from parse import *
from utils import decode_dns_name
from resolve_utils import *

ROOT_SERVER_IP = "198.41.0.4"

def resolve_recursive(query_server, domain_name, record_type: Type):
    try:
        response = lookup_domain(query_server, domain_name, record_type, True)
        if response:
            # print(f"Response received: {response}")
            print(f"Header: {response._Header}")
            if response._Header.ANCOUNT > 0:
                ip = get_answer(response, record_type.value)
                return ip
            else:
                rcode = response._Header.get_rcode()
                print(f"No answer found in the response for {domain_name}. Erorr Code: ")
                print(rcode)
        else:
            print(f"No response received for {domain_name}")
    except Exception as e:
        print(f"Error querying {query_server}: {str(e)}")

def resolve_iterative(query_server, domain_name, record_type: Type, max_iterations=10):
    nameserver = query_server
    for i in range(max_iterations):
        print(f"Iteration {i}: Querying {nameserver} for {domain_name} (type {record_type})...")
        try:
            response = lookup_domain(nameserver, domain_name, record_type, False)
        except Exception as e:
            print(f"Error querying {nameserver}: {str(e)}")
            nameserver = ROOT_SERVER_IP  # Fallback to root server
            continue

        if response is None:
            print(f"No response from {nameserver}")
            nameserver = ROOT_SERVER_IP  # Fallback to root server
            continue

        # Check for NXDOMAIN
        if response._Header.get_rcode() == 3:  # Assuming you've implemented get_rcode()
            return f"Error: Domain {domain_name} does not exist."

        # Check if the response is an answer
        if response._Header.ANCOUNT > 0:
            ip = get_answer(response, record_type.value)
            return ip

        # Check if the response contains nameserver information
        elif response._Header.NSCOUNT > 0:
            ns_domain = get_nameserver(response)
            if ns_domain is None:
                print(f"No usable NS records found for {domain_name}. Falling back to root server.")
                nameserver = ROOT_SERVER_IP
                continue  # Go to the next iteration with the root server
            print("Got the nameserver domain: " + ns_domain)

            # Check if Additional section contains the IP
            if response._Header.ARCOUNT > 0:
                nsIP = get_nameserver_ip_from_additional_section(response)
                if nsIP:
                    print(f"Got the nameserver IP from the Additional section: {nsIP}")
                    nameserver = nsIP
                    continue

            # If not, resolve the nameserver's IP
            print(f"Resolving IP for nameserver {ns_domain}...")
            nsIP = resolve_iterative(ROOT_SERVER_IP, ns_domain, Type.A)
            if isinstance(nsIP, str) and not nsIP.startswith("Error"):
                print(f"Resolved nameserver IP: {nsIP}")
                nameserver = nsIP
            else:
                print(f"Failed to resolve nameserver IP: {nsIP}")
                nameserver = ROOT_SERVER_IP  # Fallback to root server
        else:
            print("No answer or nameserver information in response")
            nameserver = ROOT_SERVER_IP  # Fallback to root server

    return f"Error: Could not resolve {domain_name} after {max_iterations} iterations"

def lookup_domain(ip_address, domain_name, type: Type, recursion):
    query = build_query(domain_name, type, recursion)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (ip_address, 53))
    # get the response
    data, _ = sock.recvfrom(1024)
    msg_response_obj = parse_dns_packet(data)
    return msg_response_obj


def build_query(domain_name, qtype, recursion):
    msg = Message(
        Header(
            id=0x8298, # As long as we're sending only one request it can be any value, only if we are sending multiple requests we need to keep track of the id so that we can match the response with the request
            flags= QR.QUERY.value<<15 | OPCODE.QUERY.value<<11 | RD.RECURSION_DESIRED.value<<8 if recursion else RD.RECURSION_NOT_DESIRED.value<<8, # We take or of the values to set the flags as 100 | 001 => 101 so we can use the enum values directly and take or of them to set the flags 
            QDCOUNT=1, 
            ANCOUNT=0, 
            NSCOUNT=0, 
            ARCOUNT=0),
        Question(
            QNAME=domain_name,
            QTYPE=Type(qtype),
            QCLASS=Class.IN),
        None, # No Answer field in query
        None, # No Authority field in query
        None # No Additional field in query
    )
    print(msg._Header.flags & (1 << 8))
    byte_string_to_send = serialize_query_message(msg)
    return byte_string_to_send

def main():
    parser = argparse.ArgumentParser(description='DNS Query Tool')
    parser.add_argument('domain_name', type=str, help='The domain name to resolve')
    parser.add_argument('-qt', type=str, default='A', help='The type of DNS query to send')
    parser.add_argument('-rd', action='store_true', help='Enable recursion if this flag is set')
    args = parser.parse_args()
    if args.rd == True:
        ip = resolve_recursive("1.1.1.1", args.domain_name, Type[args.qt.upper()])
    else:
        ip = resolve_iterative(ROOT_SERVER_IP, args.domain_name, Type[args.qt.upper()])        

    print(ip)
    

if __name__ == '__main__':
    main()