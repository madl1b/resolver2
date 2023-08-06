import sys 
import socket
import json
import struct
import random
import time
from resolver import response_processor, response_status


if len(sys.argv[1:]) != 3 and len(sys.argv[1:]) != 4:
    print('Error: invalid arguments')
    print('Usage: client resolver_ip  resolver_port name  [timeout=5]')
    exit()

# bind to public dns ip

resolver_ip = sys.argv[1]
port = int(sys.argv[2])
name = sys.argv[3]
timeout = 10
if len(sys.argv[1:]) == 4:
    timeout = sys.argv[4]


    


client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


# header is 12 bytes and each H indicates 2 bytes. 

QNAME = b'.'.join(part.encode('utf-8') for part in name.split('.')) + b'\x00'
QTYPE = 1 # type A - get IP
QCLASS = 1 # internet class

header = struct.pack('!HHHHHH',random.randint(0,65535),0,1,0,0,0)
if resolver_ip != '127.0.0.1':
    # recursion desired
    header = struct.pack('!HHHHHH',random.randint(0,65535),256,1,0,0,0) 


mylist = name.split('.')

# Create the question and add it to the header
for part in mylist:
    query = struct.pack('!B', len(part)) + part.encode('utf-8')
    header += query

header += struct.pack('!BHH', 0, 1, 1)

# question = QNAME + struct.pack('!HH', QTYPE, QCLASS)
# query = header + question


client_socket.settimeout(timeout)

start_time = time.time()
client_socket.sendto(header, (resolver_ip, port))
time_taken = 0

# try:
    # get ip from resolver
try:
    data, addr = client_socket.recvfrom(2048) 
    time_taken = time.time() - start_time
    with open('times.out', 'a') as f:
        print(time_taken, file=f)

except socket.timeout:
    print('ERROR: timed out')
    with open('times.out', 'a') as f:
        print('5.00', file=f)
    exit()



if resolver_ip == '127.0.0.1':
    data = data.decode('utf-8')
    json_data = json.loads(data)
else:
    server_addr, answer_check, json_data = response_processor(data, header)

if 'error' in json_data.keys():
    print(json_data['error'])
    exit()


print('\nDIG ROSHAN EDITION\n')
print('  ID: ' + str(json_data['header']['id']))

flags = '  FLAGS        '

if json_data['header']['flags'] & 0b1000000000000000:
    flags += 'QR: response, '
else:
    flags += 'QR: query, '

if json_data['header']['flags'] & 0b0000010000000000:
    flags += 'AA: Authoritative Answer, '
else:
    flags += 'AA: Non-authoritative Answer, '

if json_data['header']['flags'] & 0b0000001000000000:
    flags += 'TR: truncated, '
else:
    flags += 'TR: not truncated, ' 

if json_data['header']['flags'] & 0b0000000100000000:
    flags +=  'RD: recursion desired, '
else:
    flags +=  'RD: recursion not desired, '    

if json_data['header']['flags'] & 0b0000000010000000:
    flags +=  'RA: recursion available'
else:
    flags +=  'RA: recursion unavailable'    

print(flags)

summary = '  SUMMARY      ' + 'QUERY: ' + str(json_data['header']['questions']) + ', '
summary += 'ANSWER: ' + str(json_data['header']['answers']) + ', '
summary += 'AUTHORITY: ' + str(json_data['header']['authorities']) + ', '
summary += 'ADDITIONAL: ' + str(json_data['header']['additionals'])

print(summary + '\n')
# print(json_data['additionals'])

print('  ANSWER')
for answer in json_data['answers'].keys():
    a = '  ' + json_data['answers'][answer]['name'] + '         '
    a += str(json_data['answers'][answer]['class']) + '   '
    a += json_data['answers'][answer]['type'] + '           '
    a += str(answer)
    print(a)
    # try displaying it somehow?????

print('\n')
    

