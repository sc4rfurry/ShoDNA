#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import ipaddress
from rich.console import Console
from IPy import IP
import whois
from urllib3 import disable_warnings
from user_agent import generate_user_agent
from os import name as nm
import urllib3
import json


disable_warnings()
os = nm
user_agent = generate_user_agent(os="win")
console = Console()


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    def disable(self):
        self.HEADER = ""
        self.OKBLUE = ""
        self.OKCYAN = ""
        self.OKGREEN = ""
        self.WARNING = ""
        self.FAIL = ""
        self.ENDC = ""
        self.BOLD = ""
        self.UNDERLINE = ""


class ReverseDNS:
    def __init__(self, ip):
        self.ip = ip

    def task_description(self):
        return "Reverse DNS Lookup"

    def get_reverse_dns(self):
        try:
            return socket.gethostbyaddr(self.ip)
        except socket.herror:
            return None
        except socket.gaierror:
            return None
        except socket.timeout:
            return None
        except Exception:
            return None
        except KeyboardInterrupt:
            console.print(
                "[yellow bold]" + "[~] " + "[/yellow bold]",
                "[red bold]Keyboard Interrupted[/red bold]",
                style="blink",
            )
            exit(1)


class DnsLookup:
    def __init__(self, ip):
        self.ip = ip

    def task_description(self):
        return "DNS Lookup"

    def get_dns(self):
        try:
            return socket.gethostbyname(self.ip)
        except socket.herror:
            return None
        except socket.gaierror:
            return None
        except socket.timeout:
            return None
        except Exception as e:
            console.print(e)
        except KeyboardInterrupt:
            console.print(
                "[yellow bold]" + "[~] " + "[/yellow bold]",
                "[red bold]Keyboard Interrupted[/red bold]",
                style="blink",
            )
            exit(1)


class IpType:
    def __init__(self, ip):
        self.ip = ip

    def task_description(self):
        return "Getting IP Type"

    def get_ip_type(self):
        try:
            if IP(self.ip).iptype() == "PRIVATE":
                return "Private"
            elif IP(self.ip).iptype() == "PUBLIC":
                return "Public"
            else:
                return IP(self.ip).iptype()
        except Exception:
            return "Unknown"
        except KeyboardInterrupt:
            console.print(
                "[yellow bold]" + "[~] " + "[/yellow bold]",
                "[red bold]Keyboard Interrupted[/red bold]",
                style="blink",
            )
            exit(1)


class ValidateIP:
    def __init__(self, ip):
        self.ip = ip

    def task_description(self):
        return "Validating IP"

    def validate_ip(self):
        try:
            ipaddress.ip_address(self.ip)
            return True
        except ValueError:
            return False
        except Exception as e:
            console.print(e)
        except KeyboardInterrupt:
            console.print(
                "[yellow bold]" + "[~] " + "[/yellow bold]",
                "[red bold]Keyboard Interrupted[/red bold]",
                style="blink",
            )
            exit(1)


class Whois:
    def __init__(self, ip):
        self.ip = ip

    def task_description(self):
        return "Whois Lookup"

    def get_whois(self):
        try:
            global whois_results
            whois_results = whois.whois(self.ip)
            # url = f"https://api.ipapi.is/?whois={self.ip}"
            # resp = urllib3.PoolManager().request(
            #     "GET", url, headers={"User-Agent": user_agent, "Accept": "*/*", "Origin": "https://ipapi.is", "Referer": "https://ipapi.is/", "Host": "api.ipapi.is", "Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Accept-Encoding": "gzip, deflate, br", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
            # )
            # data = resp.data.decode("utf-8")
            # whois_results = json.loads(data)
            # print(whois_results)
            return whois_results
        except Exception:
            return None
        except KeyboardInterrupt:
            console.print(
                "[yellow bold]" + "[~] " + "[/yellow bold]",
                "[red bold]Keyboard Interrupted[/red bold]",
                style="blink",
            )
            exit(1)


class GeoLocation:
    def __init__(self, ip):
        self.ip = ip

    def task_description(self):
        return "Getting Geo Location"

    def get_geo_location(self):
        try:
            url = f"https://freeipapi.com/api/json/{self.ip}"
            resp = urllib3.PoolManager().request(
                "GET", url, headers={"User-Agent": user_agent}
            )
            data = resp.data.decode("utf-8")
            data = json.loads(data)
            return data
        except Exception as e:
            print(e)
        except KeyboardInterrupt:
            console.print(
                "\n[yellow bold]" + "[~] " + "[/yellow bold]",
                "[red bold]Keyboard Interrupted[/red bold]",
                style="blink",
            )
            exit(1)

class Ip2ASN:
    def __init__(self, ip):
        self.ip = ip

    def task_description(self):
        return "Getting ASN"

    def get_asn(self):
        try:
            url = f"https://api.ipapi.is/?q={self.ip}"
            resp = urllib3.PoolManager().request(
                "GET", url, headers={"User-Agent": user_agent, "Accept": "*/*", "Origin": "https://ipapi.is", "Referer": "https://ipapi.is/", "Host": "api.ipapi.is", "Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Accept-Encoding": "gzip, deflate, br", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
            )
            data = resp.data.decode("utf-8")
            data = json.loads(data)
            return data
        except Exception as e:
            return str(e)
        except KeyboardInterrupt:
            console.print(
                "\n[yellow bold]" + "[~] " + "[/yellow bold]",
                "[red bold]Keyboard Interrupted[/red bold]",
                style="blink",
            )
            exit(1)