#!/usr/bin/python3

import nmap
import sys
import signal 
import time

scanner = nmap.PortScanner()

def sigint_handler(signum, frame):
    print ('\n[-] NmapScanner has been closed')
    sys.exit()
 
signal.signal(signal.SIGINT, sigint_handler)

 

 

print( """ 







     _   _ __  __          _____   
    | \ | |  \/  |   /\   |  __ \  
    |  \| | \  / |  /  \  | |__) | 
    | . ` | |\/| | / /\ \ |  ___/  
    | |\  | |  | |/ ____ \| |      
    |_| \_|_|  |_/_/    \_\_|      






                                                         """)


print('  Welcome, This tool made by Twins                  ')
print('<-------------------------------------------------->')

ip_addr = input("Please enter the IP adress you want to scan:")
print('The IP you entered is: ', ip_addr)
type(ip_addr)

resp = input(""" \nPlease enter the type of scan you want to run
					1)Intence Scan
					2)SYN ACK Scan 
					3)UDP Scan
					4)Comperehensive Scan
					5)Web Scan (Website IP) \n""")
print('You have selected option: ', resp)

if resp == '1':
	print("Nmap Version: ", scanner.nmap_version())
	scanner.scan(ip_addr, '1-1024', '--min-hostgroup -T4 -A -v -n')
	print(scanner.scaninfo())
	print("[+] Ip status: ", scanner[ip_addr].state())
	print(scanner[ip_addr].all_protocols())
	print("[+] Open Ports: ", scanner[ip_addr]['tcp'].keys())
if resp == '2':
	print("Nmap Version: ", scanner.nmap_version())
	scanner.scan(ip_addr, '1-1024', '-v -sS')
	print(scanner.scaninfo())
	print("[+] Ip status: ", scanner[ip_addr].state())
	print(scanner[ip_addr].all_protocols())
	print("[+] Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '3':
	print("[+] Nmap Version: ", scanner.nmap_version())
	scanner.scan(ip_addr, '1-1024', '-v -sU')
	print(scanner.scaninfo())
	print("[+] Ip status: ", scanner[ip_addr].state())
	print(scanner[ip_addr].all_protocols())
	print("[+] Open Ports: ", scanner[ip_addr]['udp'].keys())
elif resp == '4':
	print("[+] Nmap Version: ", scanner.nmap_version())
	scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
	print(scanner.scaninfo())
	print("[+] Ip status: ", scanner[ip_addr].state())
	print(scanner[ip_addr].all_protocols())
	print("[+] Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '5':
	print("Nmap Version: ", scanner.nmap_version())
	scanner.scan(ip_addr, '1-1024', '-sV')
	print(scanner.scaninfo())
	print("[+] Ip status: ", scanner[ip_addr].state())
	print(scanner[ip_addr].all_protocols())
	print("[+] Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp >= '6':
	print('[-] Please enter a valid option!')
	sys.exit()

# print('Host : %s (%s)' % (host, scanner[host].hostname()))
# print('State : %s' % scanner[host].state())
#      for proto in scanner[host].all_protocols():
#         print('----------')
#         print('Protocol : %s' % proto)
# 
#         lport = scanner[host][proto].keys()
#         lport.sort()
#         for port in lport:
#          	print ('port : %s\tstate : %s' % (port, scanner[host][proto][port]['state']))
      