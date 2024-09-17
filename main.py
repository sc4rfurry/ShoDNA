#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
from os import getenv, path, makedirs, getcwd
from sys import exit, argv
from rich.console import Console
from datetime import datetime
from dotenv import load_dotenv
import shodan
import requests
from time import sleep
import json
from rich.markdown import Markdown
import re


load_dotenv()
console = Console()
WORKING_DIR = getcwd()
SHODAN_API_KEY = getenv("SHODAN_API_KEY")
SHODAN_API_INFO = f"https://api.shodan.io/api-info?key={SHODAN_API_KEY}"
IDB_URL = "https://internetdb.shodan.io/"
DORKS = "DORKS.md"
QUERY = None
COUNTRY = None
INQUIRE = False
OUTPUT = None
OUTPUT_FOLDER = path.join(WORKING_DIR, "Output")
IPS = []


def banner():
    banner = r"""
 _____ _          ______ _   _   ___  
/  ___| |         |  _  \ \ | | / _ \ 
\ `--.| |__   ___ | | | |  \| |/ /_\ \
 `--. \ '_ \ / _ \| | | | . ` ||  _  |
/\__/ / | | | (_) | |/ /| |\  || | | |
\____/|_| |_|\___/|___/ \_| \_/\_| |_/ version 1.0
"""
    console.print("[bold cyan]" + banner + "[/bold cyan]")
    console.print("[bold yellow]•[/bold yellow]" * 80, "\n")


def dir_structure():
    try:
        makedirs(OUTPUT_FOLDER, exist_ok=True)
    except Exception as e:
        console.print("[bold red]Error creating directory:[/bold red]", str(e))
        exit(1)


def save_output(results):
    global OUTPUT
    try:
        dir_structure()
        if OUTPUT is None:
            OUTPUT = re.sub(r"[ :/()\"\'.,]", "_", QUERY)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        OUTPUT_FILE = f"{OUTPUT}_{timestamp}.log"
        safe_filename = path.join(OUTPUT_FOLDER, OUTPUT_FILE)
        with open(safe_filename, "w+", encoding="utf8") as f:
            json.dump(results, f, indent=4)
        console.print("\n[bold green]✓ Output Saved.[/bold green]")
        console.print(
            f"[bold yellow]• Output File:[/bold yellow] [bold cyan]{OUTPUT_FILE}[/bold cyan]"
        )
    except Exception as e:
        console.print("[bold red]Error saving output:[/bold red]", str(e))
        exit(1)
    except KeyboardInterrupt as e:
        console.print("[bold red]Keyboard Interrupt.[/bold red]")
        exit(1)


def api_info():
    try:
        console.print("[bold yellow]• Checking the API key.[/bold yellow]")
        api = shodan.Shodan(SHODAN_API_KEY)
        api.search("h4cKed")
        console.print("[bold green]✓ API key is Valid.\n")
        console.print("\n[bold yellow]• Getting API Info.[/bold yellow]")
        api_info = requests.get(SHODAN_API_INFO)
        api_info.raise_for_status()
        console.print("[bold green]✓ API Info Fetched.")
        console.print("[bold yellow]• API Info.[/bold yellow]")
        try:
            info_json = api_info.json()
            print(json.dumps(info_json, indent=4))
        except json.JSONDecodeError:
            console.print(
                "[bold red]Error: Unable to parse API info as JSON.[/bold red]"
            )
            print("Raw response:", api_info.text)
        exit(1)        
    except shodan.APIError as e:
        console.print("[bold red]Shodan API Error:[/bold red]", str(e))
    except requests.RequestException as e:
        console.print("[bold red]Request Error:[/bold red]", str(e))
    except Exception as e:
        console.print("[bold red]Unexpected Error:[/bold red]", str(e))
    


def idbSearch(Host):
    url = IDB_URL + str(Host)
    try:
        headers = {"accept": "application/json"}
        resp = requests.get(url, timeout=30, headers=headers)
        resp.raise_for_status()
        try:
            data = resp.json()
            for key in ["ip", "hostnames", "ports", "tags", "vulns", "cpes"]:
                value = data.get(key, [])
                console.print(
                    f"[bold yellow]• {key.capitalize()}:[/bold yellow] [bold cyan]\t{value}[/bold cyan]"
                )
        except json.JSONDecodeError:
            console.print(
                "[bold red]Error: Unable to parse response as JSON.[/bold red]"
            )
            print("Raw response:", resp.text)
    except requests.RequestException as e:
        console.print("[bold red]Request Error:[/bold red]", str(e))
    except Exception as e:
        console.print("[bold red]Unexpected Error:[/bold red]", str(e))
    exit(1)


def list_queries():
    try:
        with open(DORKS, "r", encoding="utf8") as dork_file:
            for line in dork_file:
                console.print(
                    Markdown(
                        line,
                        inline_code_lexer="bash",
                        justify="center",
                        style="monokai",
                    )
                )
    except Exception as e:
        console.print("[bold red]Error reading DORKS file:[/bold red]", str(e))
    exit(1)


def shdoan_scan(IPS, QUERY, COUNTRY, INQUIRE, PAGE_LIMIT):
    limit = 10 * int(PAGE_LIMIT)
    query = f"{QUERY} country:{COUNTRY}" if COUNTRY else QUERY

    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        console.print("[bold yellow]• Checking the API key.[/bold yellow]")
        api.search("h4cKed")
        console.print("[bold green]✓ API key is Valid.\n")
        console.print(
            f"[bold yellow]• Checking the Query.[/bold yellow] [bold cyan]{query}[/bold cyan]\n"
        )

        try:
            count_result = api.count(query)
            console.print(
                ":fire:", "[yellow1]Results Found: [/yellow1]", count_result["total"]
            )
            console.print(":fire:", "[yellow1]Page Limit: [/yellow1]", PAGE_LIMIT)
            console.print(":fire:", "[yellow1]Results Limit: [/yellow1]", limit)
        except (KeyError, TypeError):
            console.print(
                "[bold red]Error: Unexpected response format from Shodan API.[/bold red]"
            )
            return

        console.print(
            f"[bold green][bold cyan]~%%[/bold cyan] Host Inquiry set to [/bold green][bold yellow3]{INQUIRE}[/bold yellow3]\n"
        )
        console.print("[blue]\n" + "  " + "»" * 80 + "\n[/blue]")

        results = []

        for count, banner in enumerate(api.search_cursor(query), 1):
            ip = banner["ip_str"]
            IPS.append(ip)
            result = {"ip": ip}
            if INQUIRE:
                sleep(0.6)
                hostinfo = api.host(ip)
                result.update({
                    "ports": hostinfo.get('ports', []),
                    "organization": banner.get('org', 'N/A'),
                    "location": banner.get('location', 'N/A'),
                    "layer": banner.get('transport', 'N/A'),
                    "domains": banner.get('domains', []),
                    "hostnames": banner.get('hostnames', [])
                })
                print(f"[+] \033[1;31mIP: \033[1;m{ip}")
                print(f"[+] \033[1;31mPort: \033[1;m{hostinfo.get('ports', [])}")
                print(f"[+] \033[1;31mOrganization: \033[1;m{banner.get('org', 'N/A')}")
                print(
                    f"[+] \033[1;31mLocation: \033[1;m{banner.get('location', 'N/A')}"
                )
                print(f"[+] \033[1;31mLayer: \033[1;m{banner.get('transport', 'N/A')}")
                print(f"[+] \033[1;31mDomains: \033[1;m{banner.get('domains', [])}")
                print(f"[+] \033[1;31mHostnames: \033[1;m{banner.get('hostnames', [])}")
                print(f"\n[✓] Result: {count}. Search query: {query}")
                console.print("[blue]\n" + "  " + "»" * 80 + "\n[/blue]")
            else:
                print(f"[+] \033[1;31mIP: \033[1;m{ip}")
                result["inquire"] = False

            results.append(result)

            if count >= limit:
                break

        if not INQUIRE:
            print(f"\n[✓] Result(s): {count}. Search query: {query}")
            console.print("[blue]\n" + "  " + "»" * 80 + "\n[/blue]")

        save_output(results)

    except shodan.APIError as e:
        console.print("[bold red]Shodan API Error:[/bold red]", str(e))
    except json.JSONDecodeError as e:
        console.print("[bold red]JSON Decode Error:[/bold red]", str(e))
    except Exception as e:
        console.print("[bold red]Unexpected Error:[/bold red]", str(e))
    exit(1)


def help():
    console.print("[bold yellow]\t\t\t• Help •[/bold yellow]\n")
    console.print(
        "[bold yellow]• Usage:[/bold yellow] [bold cyan]python3 main.py -q 'QUERY' -pl 'PAGE_LIMIT' -cn 'COUNTRY' -iq[/bold cyan]"
    )
    console.print(
        """
[bold yellow]• Options:[/bold yellow] [bold cyan]
    -q      --query              Shodan Query
    -pl     --page-limit         Page Limit [green bold](Default: 1)[/green bold]
    -cn     --country            Specify the Country (US,JP,FR)
    -iq     --inquire            Fetch More Information about each Host (Hostname, Ports etc)
    -lq     --list-queries       Show the Pre-Included SHodan Dorks (Scada, Medical etc)
    -ai     --api-info           Fetch API Information (API key Required)
    -idb    --internet-db        Search Shodan using InternetDB (IP, Hostname, CPE)
    -h      --help               Print the help menu[/bold cyan]
    """
    )
    console.print(
        "[bold yellow]• Example:[/bold yellow] [bold cyan]python3 main.py -q 'apache' -pl 2 -cn 'US' -iq[/bold cyan]"
    )
    console.print(
        "[bold yellow]• Example:[/bold yellow] [bold cyan]python3 main.py -lq[/bold cyan]"
    )
    console.print(
        "[bold yellow]• Example:[/bold yellow] [bold cyan]python3 main.py -ai[/bold cyan]"
    )
    console.print(
        "[bold yellow]• Example:[/bold yellow] [bold cyan]python3 main.py -idb IP[/bold cyan]"
    )
    exit(0)


def main():
    global QUERY, COUNTRY, INQUIRE, PAGE_LIMIT
    QUERY, COUNTRY, INQUIRE, PAGE_LIMIT = None, None, False, 1

    banner()
    if len(argv) == 1:
        help()

    try:
        for i in range(1, len(argv)):
            if argv[i] == "-q":
                QUERY = argv[i + 1]
            elif argv[i] == "-pl":
                PAGE_LIMIT = int(argv[i + 1])
            elif argv[i] == "-cn":
                COUNTRY = argv[i + 1]
            elif argv[i] == "-iq":
                INQUIRE = True
            elif argv[i] == "-lq":
                list_queries()
            elif argv[i] == "-ai":
                api_info()
            elif argv[i] == "-idb":
                idbSearch(str(argv[i + 1]))
            elif argv[i] == "-h":
                help()
            else:
                if argv[i - 1] != "-q" and argv[i - 1] != "-pl" and argv[i - 1] != "-cn" and argv[i - 1] != "-idb":
                    raise argparse.ArgumentError(None, f"Unrecognized argument: {argv[i]}")

        shdoan_scan(IPS, QUERY, COUNTRY, INQUIRE, PAGE_LIMIT)
    except argparse.ArgumentError as e:
        console.print("[bold red]Argument Error:[/bold red]", str(e))
        exit(1)
    except Exception as e:
        console.print("[bold red]Unexpected Error:[/bold red]", str(e))
        exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("[bold red]Keyboard Interrupt.[/bold red]")
        exit(1)
    except Exception as e:
        console.print("[bold red]Unexpected Error:[/bold red]", str(e))
        exit(1)
