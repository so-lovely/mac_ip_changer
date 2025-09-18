from scapy.all import *
import random
import threading
import time
import subprocess


def random_mac():
    random.seed(time.time_ns())
    return "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(6))

SPOOFED_MAC = random_mac()
IFACE = r"\Device\NPF_{A04E1008-15A7-4B0E-A1D1-858163706971}" #인터페이스 본인꺼에 맞게수정

def mac2str(mac):
    return bytes.fromhex(mac.replace(':', ''))

conf.sniff_promisc = True


discover = (
    Ether(dst="ff:ff:ff:ff:ff:ff", src=SPOOFED_MAC) /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(
        op=1,
        chaddr=mac2str(SPOOFED_MAC),
        xid=RandInt(),
        flags=0x8000
    ) /
    DHCP(options=[
        ("message-type", "discover"),
        ("hostname", "test-pc"),
        "end"
    ])
)


offer_received = None
offer_event = threading.Event()

def dhcp_offer_handler(pkt):
    global offer_received
    if pkt.haslayer(DHCP):
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'message-type' and opt[1] == 2:
                offer_received = pkt
                offer_event.set()
                break

sniff_thread = threading.Thread(
    target=sniff,
    kwargs={
        'iface': IFACE,
        'prn': dhcp_offer_handler,
        'filter': "udp and (port 67 or port 68)",
        'store': 0,
        'timeout': 10
    },
    daemon=True
)
sniff_thread.start()

sendp(discover, iface=IFACE, verbose=0)


if not offer_event.wait(timeout=5):
    print("[-] No DHCP Offer received within 5 seconds. Exiting.")
    exit()

offer = offer_received
xid = offer[BOOTP].xid
offered_ip = offer[BOOTP].yiaddr
server_ip = offer[BOOTP].siaddr

for opt in offer[DHCP].options:
    if isinstance(opt, tuple) and opt[0] == "server_id":
        server_ip = opt[1]
        break



request = (
    Ether(dst="ff:ff:ff:ff:ff:ff", src=SPOOFED_MAC) /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(
        op=1,
        chaddr=mac2str(SPOOFED_MAC),
        xid=xid,
        flags=0x8000
    ) /
    DHCP(options=[
        ("message-type", "request"),
        ("requested_addr", offered_ip),
        ("server_id", server_ip),
        ("hostname", "test-pc"),
        "end"
    ])
)

ack_received = None
ack_event = threading.Event()

def dhcp_ack_handler(pkt):
    global ack_received
    if pkt.haslayer(DHCP):
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'message-type':
                if opt[1] == 5:
                    ack_received = pkt
                    ack_event.set()
                elif opt[1] == 6:
                    print("[-] DHCP NAK received")
                    ack_event.set()
                break

def extract_network_config(dhcp_ack_pkt):
    config = {
        "ip": dhcp_ack_pkt[BOOTP].yiaddr,
        "subnet_mask": None,
        "gateway": None,
        "dns_servers": []
    }

    for opt in dhcp_ack_pkt[DHCP].options:
        if isinstance(opt, tuple):
            key, value = opt[0], opt[1]
            if key == "subnet_mask":
                config["subnet_mask"] = value
            elif key == "router":
                config["gateway"] = value[0] if isinstance(value, list) else value
            elif key == "name_server":
                if isinstance(value, list):
                    config["dns_servers"] = value
                else:
                    config["dns_servers"] = [value]

    return config

def set_adapter_mac(adapter_name, mac_address):
    mac_ps_format = mac_address.replace(":", "-")
    ps_script = f'''
    Set-NetAdapter -Name "{adapter_name}" -MacAddress "{mac_ps_format}" -Confirm:$false
    '''
    result = subprocess.run(["powershell", "-Command", ps_script], capture_output=True, text=True)


def set_static_ip(adapter_name, ip, subnet_mask, gateway, dns_servers):
    prefix_length = {
        "255.255.255.128": 25,
        "255.255.255.0": 24,
        "255.255.0.0": 16,
        "255.0.0.0": 8,
    }.get(subnet_mask, 24)

    dns_str = '", "'.join(dns_servers)
    ps_script = f'''
        Remove-NetIPAddress -InterfaceAlias "{adapter_name}" -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetRoute -InterfaceAlias "{adapter_name}" -DestinationPrefix "0.0.0.0/0" -Confirm:$false -ErrorAction SilentlyContinue
        New-NetIPAddress -InterfaceAlias "{adapter_name}" -IPAddress "{ip}" -PrefixLength {prefix_length} -DefaultGateway "{gateway}"
        Set-DnsClientServerAddress -InterfaceAlias "{adapter_name}" -ServerAddresses @("{dns_str}")
    '''

    result = subprocess.run(["powershell", "-Command", ps_script], capture_output=True, text=True)

sniff_thread2 = threading.Thread(
    target=sniff,
    kwargs={
        'iface': IFACE,
        'prn': dhcp_ack_handler,
        'filter': "udp and (port 67 or port 68)",
        'store': 0,
        'timeout': 10
    },
    daemon=True
)
sniff_thread2.start()

sendp(request, iface=IFACE, verbose=0)

if not ack_event.wait(timeout=5):
    print("No DHCP ACK received. Check network or try again.")
    exit()

if ack_received:
    ack = ack_received
    dhcp_msg_type = None
    for opt in ack[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            dhcp_msg_type = opt[1]
            break

    if dhcp_msg_type == 5:
        ""
    elif dhcp_msg_type == 6:
        print("DHCP NAK received — IP assignment failed.")
    else:
        print(f"Received DHCP message type: {dhcp_msg_type}")
else:
    print("No DHCP ACK received. Check network or try again.")

if ack_received and dhcp_msg_type == 5:
    
    net_config = extract_network_config(ack_received)

    set_static_ip(
        adapter_name="이더넷", #adapter_name 본인껄로 
        ip=net_config["ip"],
        subnet_mask=net_config["subnet_mask"],
        gateway=net_config["gateway"],
        dns_servers=net_config["dns_servers"]
    )
    set_adapter_mac("이더넷", SPOOFED_MAC) # 이것도 본인껄로 수정필요
    print('Done!')

