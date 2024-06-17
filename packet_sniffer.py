#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import argparse
from colorama import init, Fore, Style
init(autoreset=True)

def argumentParse():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface the Network you want to sniff")
    options = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please provide an Interface for the Sniffing part. Use -h for more information.")

    return options


def sniff(interface):
    """Sniff packets on the given interface."""
    try:
        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    except Exception as e:
        print(f"Error occurred while sniffing on {interface}: {e}")

def process_sniffed_packet(packet):
    """Process each sniffed packet."""
    if packet.haslayer(scapy.Raw):
        process_raw_layer(packet[scapy.Raw].load)
    if packet.haslayer(http.HTTPRequest):
        process_http_layer(packet[http.HTTPRequest])

def process_raw_layer(load):
    """Process the Raw layer of the packet to find keywords."""
    keywords = ['username', 'uname', 'user', 'password', 'pass']
    try:
        for key in keywords:
            if key in load.decode('utf-8', errors='ignore'):
                length = len(load.split())
                if length > 25:
                    pass
                else:
                    print(f"{Fore.BLUE}-----------------------------------------------------------")
                    print(f"{Fore.RED}{Style.BRIGHT}Possible Username and Password pair : {load}")
                    print(f"{Fore.BLUE}-----------------------------------------------------------")
                break

    except Exception as e:
        print(f"Error processing raw layer: {e}")

def process_http_layer(http_request):
    """Gather information from the HTTPRequest layer."""
    try:
        url = http_request.Host.decode('utf-8') if isinstance(http_request.Host, bytes) else http_request.Host
        path = http_request.Path.decode('utf-8') if isinstance(http_request.Path, bytes) else http_request.Path
        full_url = str(url + path)
        if url == 'tlu.dl.delivery.mp.microsoft.com':
            pass

        elif url == 'au.download.windowsupdate.com':
            pass

        elif url == '2.tlu.dl.delivery.mp.microsoft.com':
            pass

        elif url == '11.tlu.dl.delivery.mp.microsoft.com':
            pass

        elif url == 'dl.delivery.mp.microsoft.com':
            pass

        else:
            print()
            print(f"{Fore.GREEN}Host: {url}")
            print(f"{Fore.GREEN}Full URL: {full_url}")
            print()

    except Exception as e:
        print(f"Error processing HTTP layer: {e}")

if __name__ == "__main__":
    welcome_text = r"""
  _____ ____   ____  _____  _____  ___  ____
 / ___/|    \ |    ||     ||     |/  _]|    \
(   \_ |  _  | |  | |   __||   __/  [_ |  D  )
 \__  ||  |  | |  | |  |_  |  |_|    _]|    /
 /  \ ||  |  | |  | |   _] |   _]   [_ |    \
 \    ||  |  | |  | |  |   |  | |     ||  .  \
  \___||__|__||____||__|   |__| |_____||__|\_|

Created By : Wathsala Dewmina
    """
    print(welcome_text)
    options = argumentParse()
    print("[+] Packet Sniffer successfully started....... ")
    interface = options.interface
    sniff(interface)

