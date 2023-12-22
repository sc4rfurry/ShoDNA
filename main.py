#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
from os import getenv, path, mkdir, getcwd
from sys import exit, argv
from rich.console import Console
from datetime import datetime
from dotenv import load_dotenv
import shodan
from requests import get
from time import sleep
import json
from rich.markdown import Markdown


load_dotenv()
console = Console()
WORKING_DIR = getcwd()
SHODAN_API_KEY = getenv("SHODAN_API_KEY")
SHODAN_API_INFO = "https://api.shodan.io/api-info?key=" + str(SHODAN_API_KEY)
IDB_URL = "https://internetdb.shodan.io/"
DORKS = "DORKS.md"
QUERY = None
COUNTRY = None
INQUIRE = False
OUTPUT = None
OUTPUT_FOLDER = path.join(WORKING_DIR, "Output")
OUTPUT_FILE = path.join(
    OUTPUT_FOLDER, f"{datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}.log"
)
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
    console.print("[bold cyan] " + banner + "[/bold cyan]")
    console.print("[bold yellow]•[bold yellow]" * 80, "\n")


def dir_structure():
    try:
        if not path.exists(OUTPUT_FOLDER) or not path.isdir(OUTPUT_FOLDER):
            mkdir(OUTPUT_FOLDER)
    except Exception as e:
        console.print("[bold red]Error:[/bold red]", str(e))
        exit(1)
    except KeyboardInterrupt:
        console.print("[bold red]Keyboard Interrupt.[/bold red]")
        exit(1)


def save_output():
    global OUTPUT

    try:
        dir_structure()
        if OUTPUT == None:
            OUTPUT = (
                QUERY.replace(" ", "_")
                .replace(":", "_")
                .replace("/", "_")
                .replace("(", "_")
                .replace(")", "_")
                .replace('"', "_")
                .replace("'", "_")
                .replace(".", "_")
                .replace(",", "_")
            )
        OUTPUT_FILE = f"{OUTPUT}_{datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}.log"
        with open(path.join(OUTPUT_FOLDER, OUTPUT_FILE), "w+", encoding="utf8") as f:
            for ip in IPS:
                f.write(ip + "\n")
        console.print("\n[bold green]✓ Output Saved.[/bold green]")
        console.print(
            "[bold yellow]• Output File:[/bold yellow] [bold cyan]"
            + OUTPUT_FILE
            + "[/bold cyan]"
        )
    except Exception as e:
        console.print("[bold red]Error:[/bold red]", str(e))
        exit(1)
    except KeyboardInterrupt:
        console.print("[bold red]Keyboard Interrupt.[/bold red]")
        exit(1)


def api_info():
    try:
        console.print("[bold yellow]• Checking the API key.[/bold yellow]")
        api = shodan.Shodan(SHODAN_API_KEY)
        api.search("h4cKed")
        console.print("[bold green]✓ API key is Valid.\n")
        console.print("\n[bold yellow]• Getting API Info.[/bold yellow]")
        api_info = get(SHODAN_API_INFO)
        console.print("[bold green]✓ API Info Fetched.")
        console.print("[bold yellow]• API Info.[/bold yellow]")
        print(json.dumps(api_info.json(), indent=4))
        exit(0)
    except shodan.APIError as e:
        console.print("[bold red]Error:[/bold red]", str(e))
        exit(1)
    except Exception as e:
        console.print("[bold red]Error:[/bold red]", str(e))
        exit(1)
    except KeyboardInterrupt:
        console.print("[bold red]Keyboard Interrupt.[/bold red]")
        exit(1)


def idbSearch(Host):
    global CPES, Hostnames, IP, Ports, Tags, Vulns
    CPES = []
    Hostnames = []
    IP = []
    Ports = []
    Tags = []
    Vulns = []
    url = IDB_URL + str(Host)
    try:
        headers = {"accept": "application/json"}
        resp = get(url, timeout=30, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            CPES = data["cpes"]
            Hostnames = data["hostnames"]
            IP = data["ip"]
            Ports = data["ports"]
            Tags = data["tags"]
            Vulns = data["vulns"]
            console.print(
                "[bold yellow]• IP:[/bold yellow] [bold cyan]\t"
                + str(IP)
                + "[/bold cyan]"
            )
            console.print(
                "[bold yellow]• Hostnames:[/bold yellow] [bold cyan]\t"
                + str(Hostnames)
                + "[/bold cyan]"
            )
            console.print(
                "[bold yellow]• Ports:[/bold yellow] [bold cyan]\t"
                + str(Ports)
                + "[/bold cyan]"
            )
            console.print(
                "[bold yellow]• Tags:[/bold yellow] [bold cyan]\t"
                + str(Tags)
                + "[/bold cyan]"
            )
            console.print(
                "[bold yellow]• Vulns:[/bold yellow] [bold cyan]\t"
                + str(Vulns)
                + "[/bold cyan]"
            )
            console.print(
                "[bold yellow]• CPES:[/bold yellow] [bold cyan]\t"
                + str(CPES)
                + "[/bold cyan]"
            )
            exit(0)
        else:
            console.print(
                "[bold yellow3]Error:[/bold yellow3]",
                str(resp.status_code),
                "-",
                str(resp.reason),
            )
            console.print("[bold yellow3]Response:[/bold yellow3]", str(resp.text))
            console.print("[bold yellow3]Headers:[/bold yellow3]", str(resp.headers))
            exit(1)
    except Exception as e:
        console.print("[bold red]Error:[/bold red]", str(e))
        exit(1)
    except KeyboardInterrupt:
        console.print("[bold red]Keyboard Interrupt.[/bold red]")
        exit(1)


def list_queries():
    try:
        with open(DORKS, "r+", encoding="utf8") as dork_file:
            for line in dork_file:
                console.print(
                    Markdown(
                        line,
                        inline_code_lexer="bash",
                        justify="center",
                        style="monokai",
                    )
                )
        exit(0)
    except Exception as e:
        console.print("[bold red]Error:[/bold red]", str(e))
        exit(1)
    except KeyboardInterrupt:
        console.print("[bold red]Keyboard Interrupt.[/bold red]")
        exit(1)


def shdoan_scan(IPS, QUERY, COUNTRY, INQUIRE, PAGE_LIMIT):
    limit = 10
    count = 1
    query = str(QUERY)
    page_limit = int(PAGE_LIMIT)
    if COUNTRY != None:
        query = query + " country:" + str(COUNTRY)
    else:
        query = query
    inquire = bool(INQUIRE)

    api = shodan.Shodan(SHODAN_API_KEY)
    count_result = api.count(query)
    limit = limit * int(page_limit)
    try:
        console.print("[bold yellow]• Checking the API key.[/bold yellow]")
        api.search("h4cKed")
        console.print("[bold green]✓ API key is Valid.\n")
        print("\n")
        console.print(
            f"[bold yellow]• Checking the Query.[/bold yellow] [bold cyan]{query}[/bold cyan]\n"
        )
        console.print(
            ":fire:", "[yellow1]Results Found: [/yellow1]", count_result["total"]
        )
        console.print(":fire:", "[yellow1]Page Limit: [/yellow1]", page_limit)
        console.print(":fire:", "[yellow1]Results Limit: [/yellow1]", limit)
        print("\n")
        if inquire == True:
            console.print(
                f"[bold green][bold cyan]~%%[/bold cyan] Host Inquery (Fetch More Info) set to [/bold green][bold yellow3]{inquire}[/bold yellow3]\n"
            )
            console.print("[blue]\n" + "  " + "»" * 80 + "\n[/blue]")
            for banner in api.search_cursor(query):
                sleep(0.6)
                _ports = []
                hostinfo = api.host(banner["ip_str"])
                ip = banner["ip_str"]
                IPS.append(ip)
                for port in hostinfo["ports"]:
                    _ports.append(str(port))

                print("[+] \033[1;31mIP: \033[1;m" + (banner["ip_str"]))
                print("[+] \033[1;31mPort: \033[1;m" + str(_ports))
                print("[+] \033[1;31mOrganization: \033[1;m" + str(banner["org"]))
                print("[+] \033[1;31mLocation: \033[1;m" + str(banner["location"]))
                print("[+] \033[1;31mLayer: \033[1;m" + (banner["transport"]))
                print("[+] \033[1;31mDomains: \033[1;m" + str(banner["domains"]))
                print("[+] \033[1;31mHostnames: \033[1;m" + str(banner["hostnames"]))
                print("\n[✓] Result: %s. Search query: %s" % (str(count), str(query)))
                console.print("[blue]\n" + "  " + "»" * 80 + "\n[/blue]")

                count += 1
                if count >= limit + 1:
                    break

            save_output()
        else:
            console.print(
                f"[bold green][bold cyan]~%%[/bold cyan] Host Inquery (Fetch More Info) set to [/bold green][bold yellow3]{inquire}[/bold yellow3]\n"
            )
            console.print("[blue]\n" + "  " + "»" * 80 + "\n[/blue]")
            for banner in api.search_cursor(query):
                _ports = []
                ip = banner["ip_str"]
                IPS.append(ip)
                print("[+] \033[1;31mIP: \033[1;m" + (banner["ip_str"]))

                count += 1
                sleep(0.8)
                if count >= limit + 1:
                    break
            print(
                "\n[✓] Result(s): %s. Search query: %s" % (int(count - 1), str(query))
            )
            console.print("[blue]\n" + "  " + "»" * 80 + "\n[/blue]")
            save_output()
    except shodan.APIError as e:
        console.print("[bold red]Error:[/bold red]", str(e))
        exit(1)
    except Exception as e:
        console.print("[bold red]Error:[/bold red]", str(e))
        exit(1)
    except KeyboardInterrupt:
        console.print("[bold red]Keyboard Interrupt.[/bold red]")
        exit(1)


def help():
    console.print("[bold yellow]\t\t\t• Help •[/bold yellow]\n")
    console.print(
        "[bold yellow]• Usage:[/bold yellow] [bold cyan]python3 main.py -q 'QUERY' -pl 'PAGE_LIMIT' -cn 'COUNTRY' -iq[/bold cyan]"
    )
    console.print(
        """\n[bold yellow]• Options:[/bold yellow] [bold cyan]
        -q      --query              Shodan Query
        -pl     --page-limit         Page Limit [green bold](Default: 1)[/green bold]
        -cn     --country            Specify the Country (US,JP,FR)
        -iq     --inquire            Fetch More Information about each Host (Hostname, Ports etc)
        -lq     --list-queries       Show the Pre-Included SHodan Dorks (Scada, Medical etc)
        -ai     --api-info           Fetch API Information (API key Required)
        -idb    --internet-db        Search Shodan using InternetDB (IP, Hostname, CPE)
        -h      --help               Print the help menu[/bold cyan]"""
    )
    console.print(
        "\n[bold yellow]• Example:[/bold yellow] [bold cyan]python3 main.py -q 'apache' -pl 2 -cn 'US' -iq[/bold cyan]"
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
    console.print(
        "[bold yellow]• Example:[/bold yellow] [bold cyan]python3 main.py -h[/bold cyan]"
    )
    exit(0)


def main():
    global QUERY, COUNTRY, INQUIRE, PAGE_LIMIT
    QUERY = None
    COUNTRY = None
    INQUIRE = False
    PAGE_LIMIT = 1

    banner()
    try:
        if len(argv) == 1:
            help()
        else:
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
                    continue

        shdoan_scan(IPS, QUERY, COUNTRY, INQUIRE, PAGE_LIMIT)
    except argparse.ArgumentError as e:
        console.print("[bold red]Error:[/bold red]", str(e))
        exit(1)
    except KeyboardInterrupt:
        console.print("[bold red]Keyboard Interrupt.[/bold red]")
        exit(1)
    except Exception as e:
        console.print("[bold red]Error:[/bold red]", str(e))
        exit(1)


if __name__ == "__main__":
    main()
