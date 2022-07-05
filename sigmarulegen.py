#!/usr/bin/env python3

import re
import socket
import sys
import uuid

def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except:
        return False

def run(instr):
    splpat = r'[,\s]+'
    elems = re.split(splpat, instr)

    rules = []

    ippat = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    dnspat = r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}'
    hashpat = r'([a-z0-9]{32}){1,2}'

    for a in elems:
        ruleid = uuid.uuid4()
        if re.fullmatch(ippat, a):
            if valid_ip(a):
                ruleid2 = uuid.uuid4()
                rule = f"""title: Communicating With Bad IP
id: {ruleid}
status: experimental
description: Detect connections to or from bad IP
author: Kevin Snider
logsource:
    category: firewall
detection:
    select_outgoing:
        dst_ip:
            - '{a}'
    select_incoming:
        src_ip:
            - '{a}'
    condition: 1 of select*
falsepositives:
    - Unknown
level: high
---
title: Network Connection To Bad IP
id: {ruleid2}
status: experimental
description: Detect network connections to a bad IP
author: Kevin Snider
logsource:
    category: network_connection
detection:
    select_outgoing:
        Initiated: 'true'
        DestinationIp:
            - '{a}'
    select_incoming:
        Initiated: 'false'
        SourceIp:
            - '{a}'
    condition: 1 of select*
falsepositives:
    - Unknown
level: high"""
            else:
                raise Exception(f"{a} is not a valid IP address")
        elif re.fullmatch(dnspat, a):
            ruleid2 = uuid.uuid4()
            rule = f"""title: Detect DNS Query
id: {ruleid}
status: experimental
description: Detect dns queries of bad domain
author: Kevin Snider
logsource:
    category: dns
detection:
    selection:
        query:
            - '{a}'
    condition: selection
falsepositives:
    - Unknown
level: high
---
title: Detect Network Connection To Malicious Domain
id: {ruleid2}
status: experimental
description: Detect network connections to malicious domain
author: Kevin Snider
logsource:
    category: network_connection
detection:
    selection:
        Initiated: 'true'
        DestinationHostname:
            - '{a}'
    condition: selection
falsepositives:
    - Unknown
level: high"""
        elif re.fullmatch(hashpat, a):
            if len(a) == 32:
                rule = f"""title: Malicious MD5 Hash
id: {ruleid}
status: experimental
description: Detect malicious files using md5 hash
author: Kevin Snider
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Hashes|contains:
            - 'MD5={a.upper()}'
    condition: selection
falsepositives:
    - Unknown
level: high"""
            elif len(a) == 64:
                rule = f"""title: Malicious SHA256 Hash
id: {ruleid}
status: experimental
description: Detect malicious files using sha256 hash
author: Kevin Snider
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Hashes|contains:
            - 'SHA256={a.upper()}'
    condition: selection
falsepositives:
    - Unknown
level: high"""
            else:
                raise Exception(f"This should never happen")
        else:
            raise Exception(f"{a} is an unknown type")
        rules.append(rule)
    
    return "\n---\n".join(rules)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise Exception("Need a string argument when running as a script")
    else:
        result = run(sys.argv[1])
        print(result)
