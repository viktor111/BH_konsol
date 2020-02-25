# BH_konsol

BH_konsol (black hat konsol) Its all in one tool made for ethical hacking and pen testing.  

## Tools
 
```
mac-change
```
Change your mac address just with a simple command whenever you want.
```
net-scan
```
Scan all the devices on your wifi and diplay infromataion such as ip address mac address and manufacturer (make sure to include /24 at the end of the ip or you will not see all devices.)
```
net-spoof
```
Trick the router and the victim by sending ARP packet to both with the MAC address of each other and become man in the middle. (you must enable forwarding and if using wifi must have wifi chpset wich can be in monitor mode)
```
sniffer
```
Once you used net spoof to become man in the middle you can use sniffer tool to watch for incoming http requests (GET, POST, etc) and extract data like url username and password.
```
net-stop
```
net-stop creates a queue in wich incoming packets to the traget with the spoofer are held and dropped so the target never gets a response.

```
dns-spoof
```
Captures and modifes DNS response so you can redirect the target IP to a new host

### Usage

Usage is ver simple.

cd in the BH_konsol dir

run the main.py
(dont forget the sudo or some tools will not work)
```
sudo python3 main.py
```
To use a tool
```
run [tool number here] [options here]
```
To get help
```
help
```
To get all commands
```
commands
```
To get info about tool 
```
info [tool num]
```

## Prerequisites
Simply run REQUREMENTS.txt with pip

```
pip install -r REQUREMENTS.txt
```

## Built With

* [Python 2.7/3](https://www.python.org/) - Language used to write the tools

* [Ubuntu Linux](https://ubuntu.com/) - OS used

## Authors

* **Viktor Draganov** - *Initial work* - [viktor111](https://github.com/viktor111)
