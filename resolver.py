import sys 
import socket
import re
import struct
import random
import json
import threading
import time
import signal 
from concurrent.futures import ThreadPoolExecutor

CNAME = 5
SOA = 6






def get_address(packet, offset):
    addr = get_answer_v2(packet, offset)
    offset = record_offset(packet, offset)
    return addr.decode()[:-1],offset


def get_answer_v2(packet, offset):
    if packet[offset] == 0:
        return b''
    
    if packet[offset] >= 0b11000000:
        pointer = (((packet[offset] & 0b00111111) << 8) | packet[offset + 1])
        return get_answer_v2(packet, pointer)


    length = packet[offset] + 1
    address = packet[offset + 1:offset + length] + '.'.encode('utf-8')


    address += get_answer_v2(packet, offset + length)

    return address

def update_offset(packet, offset):
    while True:
        offset += 1
        if packet[offset] == 0:
            break
        if packet[offset] == 0b11000000:
            offset += 1
            break

    return offset

def get_ip(packet,offset):
    ip_address = ''
    for i in range(offset, offset + 4):
        ip_address += str(packet[i])
        ip_address += '.'

    return ip_address[:-1]

def run_sub_query(packet, server_addrs):
    try: 
        answer_check = 1
        server_addr = ''
        # display = None
        while True:
            for addr in server_addrs:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(10)
                s.sendto(packet, (addr, 53))     
                try:
                    root_data, _ = s.recvfrom(512)
                    s.close()
                    server_addr, answer_check, display = response_processor(root_data, packet)
                    if answer_check == -2:
                        continue
                    break
                except socket.timeout:
                    s.close()
                    return '',-1,dict()


            if answer_check == 1:
                return server_addr, answer_check, display  

            if answer_check == 0:
                server_addrs = display['additionals']

    except socket.timeout:
        print('Resolver Error: timed out')
        s.close()
        return '',-1,dict()
    

def response_status(flags):
    rcode = flags & 0b1111
    if rcode == 0:
        return 0,'query successful'
    if rcode == 1:
        return -1, 'format ERROR: server can\'t interpret query'
    if rcode == 2:
        return -2,'ServFail ERROR: server failed'
    if rcode == 3:
        return -1, 'NXDomain ERROR: Non-existent domain'
    if rcode == 4:
        return -1, 'NotImp ERROR: NS does not support this kind of query'
    if rcode == 5:
        return -1, 'Refused ERROR: NS refuses to perform the specified operation'
    else:
        return -1,f'ERROR: {rcode}'


def response_processor(packet, domain_packet):

    header = struct.unpack('!HHHHHH', packet[:12])
    trans_id = header[0]
    flags = header[1]
    question_count = header[2]
    answer_count = header[3]
    authority_count = header[4]
    additional_count = header[5]

    response_check, message = response_status(flags)
    if response_check:
        return message, response_check, {'error': message}
# # DNS Questions (Variable length)
# # header is 12 bytes
    offset = 12
    questions = []
    for _ in range(question_count):
        # adding 4 puts offset past Qtype and Qclass
        q, offset = get_address(packet, offset)
        questions.append(q)
        offset += 4


    cnames = []
    answers = dict()
    for _ in range(answer_count):
        ns_name, offset = get_address(packet, offset)

        q_type = (packet[offset]<<8) | (packet[offset + 1])
        q_class = (packet[offset + 2]<<8) | (packet[offset + 3])
        data_length = (packet[offset + 8]<<8) | (packet[offset + 9])
        offset += 10

        # check if type A
        if q_type == 1:
            addr = get_ip(packet,offset)
            answers[addr] = {'type': 'A', 'class': 'IN', 'name': ns_name}
            offset += data_length
            continue
        # move offset to next record and try again
        ns_name, offset = get_address(packet, offset)
        if  q_type  == CNAME:
            cnames.append(ns_name)

    search_name, _ = get_address(domain_packet, 12)  
    auth_ns = list()
    ans_names = list()
    for _ in range(authority_count):
        # collect authority servers
        name, offset = get_address(packet, offset)
        offset += 10
        address, offset = get_address(packet, offset)
        if search_name == name:
            ans_names.append(address)
        auth_ns.append(address)


    # now check if additional records has any of these ns

    additionals = []
    for _ in range(additional_count):
        ns,offset = get_address(packet, offset)

        q_type = (packet[offset]<<8) | (packet[offset + 1])
        data_length = (packet[offset + 8]<<8) | (packet[offset + 9])
        offset += 10
        if q_type == 1 and ns in auth_ns:
            ip = get_ip(packet, offset)
            additionals.append(ip)
            # glue type record processing 

        offset += data_length

    header_dict ={
        'id': trans_id,
        'flags': flags,
        'questions': question_count,
        'answers': answer_count,
        'authorities': authority_count,
        'additionals': additional_count
    }

    display = dict()
    display['header'] = header_dict
    display['questions'] = questions
    display['answers'] = answers
    display['auths'] = auth_ns
    display['additionals'] = additionals

    for ans in answers.keys():
        return ans, 1, display 

 
    for cname in cnames:
        # print('hit cname case')
        cname_packet = sub_query(cname)                
        root_ips = get_root_ips()
        new_server_ip, check, display = run_sub_query(cname_packet, root_ips)
        if check == 1:
            return new_server_ip, 1, display        
        if check == -1:
            return 'Error: timed out', -1, dict()
        

    for addi in additionals:
        return addi, 0, display

    # get ip of auth ns and make a new query w that as the destination
    for server_name in auth_ns:
        new_packet = sub_query(server_name)
        new_server_ip, check, all_data = run_sub_query(new_packet, get_root_ips())  
        if check == -1:
            return 'Error: timed out', -1, dict()
        # run_sub_query not returning

        auth_addr, check, display= run_sub_query(domain_packet, all_data['answers'].keys())
        if check == 1: 
            return auth_addr, 1, display
        if check == -1:
            return 'Error: timed out', -1, dict()
            
    return 'no answer resolved',-1, display
 
def record_offset(dns_packet_data, offset):
    # process length of domain name in query - variable length so loop needed
    while True:
        length = dns_packet_data[offset]
        if length == 0:
            offset += 1
            break
        elif length >= 0b11000000: # compression
            offset += 2
            break

        offset = offset + length + 1

    return offset


def sub_query(name):
    header = struct.pack('!HHHHHH',random.randint(0,65535),0,1,0,0,0)
    mylist = name.split('.')
    # Create the question and add it to the header
    for part in mylist:
        query = struct.pack('!B', len(part)) + part.encode('utf-8')
        header += query

    header += struct.pack('!BHH', 0, 1, 1)  

    return header

def get_root_ips():
    ips = []
    with open("named.root") as hint:
        root_info = hint.read() 
        root_ips = re.findall('((\d+\.){3}\d+)', root_info)
        ips.append(root_ips[0][0])       
    return ips
    
def run(resolverSocket, packet):


    ips = get_root_ips()
    try: 

        server_addrs = ips
        domain_packet = packet
        rcode_error = 0
        error = 0
        timeout_check = 0
        while True:
            for addr in server_addrs:
                serverTalker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                serverTalker.settimeout(5)
                # print(f'requesting this address: {addr}')
                serverTalker.sendto(packet, (addr, 53))    
                # print(f'sending??')

                try:
                    root_data, _ = serverTalker.recvfrom(512)
                    server_addr, answer_check, display = response_processor(root_data, domain_packet)
                    if answer_check == -2:
                        continue
                    break
                except socket.timeout:
                    timeout_check = 1
                    # print('timed out!!!\n')
                    break
            # MAYYBE CORRECT
            if timeout_check:
                error_msg = {'error': 'resolver timed out'}
                resolverSocket.sendto(json.dumps(error_msg).encode(), clientAddress)
                return

            if answer_check in [1,-1]:
                display_data = json.dumps(display)
                resolverSocket.sendto(display_data.encode('utf-8'), clientAddress)
                return

            if not answer_check:

                server_addrs = display['additionals']

                

                # resolve()

    except KeyboardInterrupt:
        print('idk it fucked up')



if __name__ == "__main__":


    if len(sys.argv[1:]) not in [1,2]:
        print('Error: invalid arguments')
        print('Usage: resolver port  [timeout=5]')
        exit()


    check = re.findall('\d+', sys.argv[1])
    if check:
        p = int(check[0])
        if p < 1 or p > 65535:
            print('Error: invalid arguments')            
            print('Usage: resolver port between 1 and 65535')
            exit()
    else:
        exit()


    executor = ThreadPoolExecutor(max_workers=100)

    try:
        # resolverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # port = int(sys.argv[1])
        # resolverSocket.bind(('localhost', port))
        resolverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        port = int(sys.argv[1])
        resolverSocket.bind(('localhost', port))
        while True:

            packet, clientAddress = resolverSocket.recvfrom(512) 
            tup = (resolverSocket, packet)
            thread = threading.Thread(target=run, args=tup)
            try:
                time.sleep(0.05)
                thread.start()
            except Exception as d:
                print(d)


    except Exception as e:
        print(e)
        pass




