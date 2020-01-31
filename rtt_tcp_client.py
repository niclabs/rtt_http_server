import httplib
import sys
if len(sys.argv)!=3:
    print('Usage: python ping_tcp_client.py <host_ip> <host_port>')

IP = str(sys.argv[1])
PORT = int(sys.argv[2])
print("Client connecting to: ", IP, PORT)

c = httplib.HTTPConnection(IP+":"+str(PORT))

#Hangle connection refused
c.request("GET", "/rtt")
response = c.getresponse()
print response.status, response.reason
data = response.read()
print data
c.close()