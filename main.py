import argparse
import nmap
from pprint import pprint
import os

uid = os.geteuid()
if uid != 0:
    print("You aren't root, please run this with sudo")
    exit(-1)

parser = argparse.ArgumentParser(description='Add some integers.')
parser.add_argument('-target', '-t', type=str, help='IP do host alvo', required=True)
parser.add_argument('--udp', '-u', help='Deseja usar UDP', action='store_true')
parser.add_argument('--ports', '-p', help='Portas a serem escaneadas eg. 22-1024', type=str, default='0-1023')

args = parser.parse_args()
target = args.target
ports = args.ports

# Initialize Scanner and add arguments based on argv
nm = nmap.PortScanner()
scan_arguments = '-Pn -sSV'
if args.udp:
    scan_arguments += ' -sU'

try:
    scan = nm.scan(hosts=target, ports=ports, arguments=scan_arguments) 
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
            lport = nm[host][proto].keys()
            for port in lport:
                print ('port : %s\tstate : %s\tproduct:%s\t version:%s' % (
                    port,
                    nm[host][proto][port]['state'],
                    nm[host][proto][port]['product'] or nm[host][proto][port]['name'],
                    nm[host][proto][port]['version']
                ))

except Exception as error:
    print(error)