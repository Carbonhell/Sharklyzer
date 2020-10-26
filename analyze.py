import os
import sys
from datetime import datetime
import socket
import pyshark

try:
    cap = sys.argv[1]
    websites = sys.argv[2]
except:
    print('Usage: python analyze.py cap')
    print('\tcap: filename of a .cap file')
    print('\twebsites: filename of a .txt file containing website names, one per line')
    sys.exit("Error: Missing arguments")

websites = [x for x in open(websites, 'r').read().split('\n')]
local_ip = socket.gethostbyname(socket.gethostname())
print("Local ip: " + local_ip)
start_time = datetime.now()
print("Current time: " + str(start_time))
print("Starting analysis...")
analyzer = pyshark.FileCapture(cap)
https = 0
third_party = 0
for packet in analyzer:
    # Is it HTTPS?
    try:
        # print("src: " + packet.ip.src + ", equal? " + str(packet.ip.src == local_ip))
        # print("tcp port: " + packet.tcp.port + ", equal? "+ str(packet.tcp.port == '443'))
        # print("Match? " + str((packet.tcp.port == '443') and (packet.ip.dst == local_ip)))
        # if packet.ip.dst == local_ip and packet.tcp.port == '443':
        if packet.tcp.port == '443':
            # print("Found!")
            https += 1
    except:
        pass
    # Is it a third-party http request?
    try:
        # if packet.ip.src == local_ip and packet.http and any([x for x in websites if not (packet.http.host == x or 'www.' + packet.http.host == x)]):
        if packet.http and any([x for x in websites if not (packet.http.host == x or 'www.' + packet.http.host == x)]):
            third_party += 1
    except:
        pass

end_time = datetime.now() - start_time
print("\aAnalysis completed.")
print("HTTPS: " + str(https))
print("Third party http packets: " + str(third_party))
print("Time: " + str(end_time.seconds) + " seconds")
print("File size: " + str(os.path.getsize(cap) / 1000000) + ' MB')  # bytes to mb
analyzer.close()  # Errors out. PyShark doesn't close the event loop properly.
