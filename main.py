import scapy.all as scapy
import pyfiglet
import http as server
import subprocess
import sys

from mac_vendor_lookup import MacLookup
from prettytable import PrettyTable

def start_text():
    intro_text_1 = pyfiglet.figlet_format('BH\nkonsole', font='5lineoblique')
    intro_text_2 = pyfiglet.figlet_format('by zvado', font='digital')

    print(intro_text_1)
    print(intro_text_2)

start_text()

event = False

class Mac_change:
    def __init__(self,id ,name, info):
        self.id = id
        self.name = name
        self.info = info
    def change_mac(self, interface, new_mac):
        print(f'[+] Tool started!')

        commands_1 = ['ifconfig', interface, 'down']
        commands_2 = ['ifconfig',  interface, 'hw', 'ether', new_mac]
        commands_3 = ['ifconfig', interface, 'up']

        subprocess.call(commands_1)
        print(f'[+] Interface {interface} down')
        subprocess.call(commands_2)
        print(f'[+] Changing MAC address to new one')
        subprocess.call(commands_3)
        print(f'[+] MAC address changed to {new_mac}.')

class Net_detect:
    def __init__(self,id ,name, info):
        self.id = id
        self.name =  name
        self.info = info
    def detect(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcats = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_request_broadcast = broadcats/arp_request
        answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        mac_table = PrettyTable(['IP', 'MAC address', 'Vendor'])
        for el in answered:
            mac_table.add_row([el[1].prsc, el[1].hwsrc, MacLookup.lookup(el[1].hwsrc)])
def set_tools():
    info_mac_change = 'Changes your MAC address\n options are interface and new_mac.'
    info_net_detect = 'Detects all devices in the network\n options are yourIP/24'

    mac_change = Mac_change(0,'mac_change', info_mac_change)
    net_detect  = Net_detect(1,'net_detect', info_net_detect)

    return [mac_change, net_detect]

def display_tools():
    tools = set_tools()
    for tool in tools:
        print(f'{tool.id} - {tool.name}')
    event = True

def display_commands():
    help_table = PrettyTable(['Commands', 'Actions', 'Example'])
    help_table.add_row(['show', 'Lists all tools', 'show'])
    help_table.add_row(['help', 'Lists commands', 'help'])
    help_table.add_row(['run', 'Run a tool by selecting a number', 'run 0'])
    help_table.add_row(['info', 'Information about paricular tool', 'info 0'])
    help_table.add_row(['bye', 'Exit the programm', 'bye'])
    print(help_table)

def display_help():
    print('To use the tool list all commands type commands')
    print('This is all in one tool made by zvado.')
    print('This tool is made for balack hat hackers but if anyone can use it as well.')

def exit():
    print('\n bye :p')
    sys.exit()

def options_list(list_command):
    options = []
    for index in range(2, len(list_command)):
       command = list_command[index]
       options.append(command)
    return options

def event_builder(command):
    event = []
    try:
        list_command = command.split()
        tool_number = list_command[1]
        options = options_list(list_command)
        event.append(tool_number)
        event.append(options)
    except IndexError:
        print('[-] Input tool number.')
        read_command()

    return event


def run_tool(event):
    print(event)

    #set_tools()[0].change_mac('enp3s0', '70:85:c2:06:ea:c4')
def read_command():
    set_tools()
    try:
        command_input = input('->> ')
    except KeyboardInterrupt:
        exit()
    #check what is the command
    if command_input == 'show':
        display_tools()
    if command_input == 'help':
        display_help()
    if command_input == 'commands':
        display_commands()
    if command_input == 'bye':
        exit()
    if 'run'in command_input:
        event = event_builder(command_input)
        run_tool(event)

while True:
    read_command()


