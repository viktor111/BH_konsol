import scapy.all as scapy
import pyfiglet
import http as server
import subprocess
import sys
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
        print(f'[+] Changing MAC address to {new_mac}!')

        commands_1 = ['ifconfig', interface, 'down']
        commands_2 = ['ifconfig', 'hw', 'ether', new_mac]
        commands_3 = ['ifconfig', interface, 'up']

        subprocess.call(commands_1)
        subprocess.call(commands_2)
        subprocess.call(commands_3)

class Net_detect:
    def __init__(self,id ,name, info):
        self.id = id
        self.name =  name
        self.info = info
    #ToDo method to for detect devices in network
#method to set all the tools
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
    print(help_table)

def display_help():
    print('To use the tool list all commands type commands')
    print('This is all in one tool made by zvado.')
    print('This tool is made for balack hat hackers but if anyone can use it as well.')


def run_tool(tool_num):
    print(tool_num)

    set_tools()[0].change_mac('enp3s0', '70:85:c2:06:ea:c4')
    # ToDo run a tool class method based on tool number


def read_command():
    #set the tools before reading command
    set_tools()
    tool_num = 0

    command = input('->> ')
    #check what is the command
    if command == 'show':
        display_tools()
    if command == 'help':
        display_help()
    if command == 'commands':
        display_commands()
    if 'run'in command:
        try:
            list_command = command.split()
            tool_num = list_command[1]
        except IndexError:
            print('[-] Please select tool number.')
            return read_command()
        run_tool(tool_num)

while True:
    read_command()








