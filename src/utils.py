def decode_dns_name(name_bytes):
    labels = []
    i = 0
    while i < len(name_bytes):
        length = name_bytes[i]
        if length == 0:
            break
        i += 1
        labels.append(name_bytes[i:i+length].decode())
        i += length
    return '.'.join(labels)
