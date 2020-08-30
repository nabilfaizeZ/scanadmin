import nmap
import os

scanner = nmap.PortScanner()

os.system('clear')

print("Jenis Scan yang dapat dilakukan : ")
print("\n1. Fast Scan")
print("\n2. Detailed Scan")

jenis_scan = int(input("\nMasukkan jenis scan yang diinginkan : "))

target = input("\nMasukkan IP Address Target : ")

print("\nVersi NMap yang dipakai : ", scanner.nmap_version())

if(jenis_scan == 1):
    scanner.scan(hosts=target, arguments='--top-ports 100 -sS -T4 -Pn -v')
elif(jenis_scan == 2):
    scanner.scan(hosts=target, ports='1-1024', arguments='-sV -sS -T4 -Pn -v')

print(scanner.scanstats())

print("Command line yang digunakan : ", scanner.command_line(),"\n\n")
print('-'*50)
print("Hasil NMap : ")
print('-'*50)
print("\nStatus target",target,str("\t"*4) + "= ",scanner[target].state())

open_port = []

for port in scanner[target]['tcp'].keys():
    open_port.append(port)

print("Port yang terbuka pada target",target,"adalah\t= ",open_port)
    