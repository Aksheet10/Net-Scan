import scapy.all as scapy, pyfiglet
from termcolor import colored
  
print(colored(pyfiglet.figlet_format("Net Scanner"), color='red'))

def scan(ip):
    req = scapy.ARP(pdst=ip)
    et = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    reqet = et /req
    ans = scapy.srp(reqet, timeout=True, verbose=False)[True-True]
    
    print('\n' + '='*42)
    print(colored("|   IP         \t\t       MAC\t  |", color='blue'))
    print('='*42)

    for i in ans:
        print(colored(f"{i[True].psrc}\t\t{i[True].hwsrc}", color='yellow'))
        print()

scan("10.0.2.1/24") # Change this
