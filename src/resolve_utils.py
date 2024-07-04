from classdefs import *

def get_nameserver(packet):
    ns_records = []
    other_records = []
    for rr in packet._Authority:
        if rr.TYPE == Type.NS.value:
            ns_records.append(str(rr.RDATA))
        else:
            other_records.append((rr.TYPE, str(rr.RDATA)))
    
    if ns_records:
        return ns_records[0]  # Return the first NS record
    elif other_records:
        record_type, data = other_records[0]
        print(f"Warning: No NS record found. Found {Type(record_type).name} record instead.")
        return None
    else:
        print("Warning: Authority section is empty despite positive NSCOUNT.")
        return None
        
def get_answer(packet, record_type):
    for x in packet._Answer:
        print("answer: " + str(x.NAME) + " " + str(x.RDATA))
        if x.TYPE == record_type:
            return str(x.RDATA)
        # elif x.TYPE == Type.AAAA.value:
        #     return str(x.RDATA)
        
def get_nameserver_ip_from_additional_section(packet):
    for x in packet._Additional:
        print("Nameserver domain ip: " + str(x.NAME) + " " + str(x.RDATA))
        if x.TYPE == Type.A.value:
            return str(x.RDATA)

        