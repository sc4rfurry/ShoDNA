#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, redirect, url_for
from os import getcwd, getenv, path, makedirs, listdir
from datetime import datetime
import secrets
import getpass
import requests
import shodan
from rich.console import Console
from dotenv import load_dotenv
from markdown2 import Markdown
from uuid import uuid4
import json
import re
from shlex import split
from subprocess import run, PIPE, check_output
from sys import platform
from utils.utils import IpType, ReverseDNS, DnsLookup, Whois, GeoLocation, Ip2ASN
import nmap3



####################
#     Constants    #
####################
WORKING_DIR = getcwd()
console = Console()
OUTPUT_SEARCH_FOLDER = path.join(WORKING_DIR, "output", "search")
IDB_SEARCH_FOLDER = path.join(WORKING_DIR, "output", "idb")
TAGS_FOLDER = path.join(WORKING_DIR, "output", "tags")
ENUM_FOLDER = path.join(WORKING_DIR, "output", "enum")
PSCAN_Folder = path.join(WORKING_DIR, "output", "enum", "portscan")
ENV_FILE = path.join(WORKING_DIR, ".env")


####################
#     Dir Check    #
####################
def folder_check():
    if not path.exists(OUTPUT_SEARCH_FOLDER):
        console.print(
            "[bold red]Creating output folder for shodan search results.[/bold red]"
        )
        try:
            makedirs(OUTPUT_SEARCH_FOLDER)
        except Exception as e:
            console.print("[bold red]Error:[/bold red]", str(e))
            exit(1)
    else:
        pass
    if not path.exists(IDB_SEARCH_FOLDER):
        console.print("[bold red]Creating output folder for idb results.[/bold red]")
        try:
            makedirs(IDB_SEARCH_FOLDER)
        except Exception as e:
            console.print("[bold red]Error:[/bold red]", str(e))
            exit(1)
    else:
        pass
    if not path.exists(TAGS_FOLDER):
        console.print("[bold red]Creating output folder for tags and uuids.[/bold red]")
        try:
            makedirs(TAGS_FOLDER)
        except Exception as e:
            console.print("[bold red]Error:[/bold red]", str(e))
            exit(1)
    else:
        pass
    if not path.exists(ENUM_FOLDER):
        console.print("[bold red]Creating output folder for enum results.[/bold red]")
        try:
            makedirs(ENUM_FOLDER)
        except Exception as e:
            console.print("[bold red]Error:[/bold red]", str(e))
            exit(1)
    else:
        pass
    if not path.exists(PSCAN_Folder):
        console.print("[bold red]Creating output folder for enum results.[/bold red]")
        try:
            makedirs(PSCAN_Folder)
        except Exception as e:
            console.print("[bold red]Error:[/bold red]", str(e))
            exit(1)
    else:
        pass


#########################
#       App Config      #
#########################
USER = getpass.getuser()
folder_check()
app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_urlsafe(16)


#########################
#    Global Variables   #
#########################
load_dotenv()
SHODAN_API_KEY = getenv("SHODAN_API_KEY")
SHODAN_API_INFO = "https://api.shodan.io/api-info?key=" + str(SHODAN_API_KEY)
DORKS = "DORKS.md"
README = "README.md"
ABOUT = "ABOUT.md"
IDB_URL = "https://internetdb.shodan.io/"
AVATAR_URL = "https://robohash.org/"
IPS = []
TAGS = ["search", "idb"]
QUERY = None
COUNTRY = None
INQUIRE = False
OUTPUT = None
UNIQUE_IDS = []
DATE_TIME = str(datetime.now()).replace(" ", "--")
WHITE_LIST_ENDPOINTS = [
    "index",
    "home",
    "search",
    "internetDB",
    "history",
    "dorks",
    "about",
    "more_info",
]
API_DEPENDANT_ENDPOINTS = ["search"]


####################
# Custom Functions #
####################
def save_uuids(UNIQUE_ID, query, OUTPUT, TAG):
    uuid_data = {}
    OUTPUT = (
        OUTPUT.replace(" ", "_")
        .replace("\n", "_")
        .replace("\r", "_")
        .replace("\t", "_")
        .replace("\v", "_")
    )
    file_path = path.join(TAGS_FOLDER, "uuids.json")

    if path.exists(file_path):
        with open(file_path, "r", encoding="utf8") as file:
            try:
                uuid_data = json.load(file)
            except json.decoder.JSONDecodeError:
                uuid_data = {}

    uuid_data[str(UNIQUE_ID)] = {
        "query": query,
        "output": OUTPUT,
        "date": DATE_TIME,
        "tag": TAG,
    }

    with open(file_path, "w", encoding="utf8") as file:
        json.dump(uuid_data, file, indent=4)


def load_search_history_data():
    FILE_PATH = path.join(TAGS_FOLDER, "uuids.json")
    try:
        with open(FILE_PATH, "r", encoding="utf8") as file:
            try:
                data = json.load(file)
                return data
            except json.decoder.JSONDecodeError:
                data = {}
                return data
    except Exception as e:
        error = str(e)
        render_template("500.html", error=error)


def save_idb_output(QUERY, CPES, Hostnames, Ports, Tags, Vulns, SC, RN, TXT, HDRS, TAG):
    global OUTPUT, query, err
    query = str(QUERY)
    err = None
    UNIQUE_ID = uuid4()
    if UNIQUE_ID not in UNIQUE_IDS:
        UNIQUE_IDS.append(UNIQUE_ID)
    else:
        UNIQUE_ID = uuid4()
        UNIQUE_IDS.append(UNIQUE_ID)
    OUTPUT = path.join(
        IDB_SEARCH_FOLDER, str(UNIQUE_ID) + "_" + str(query) + "_" + str(TAG) + ".json"
    )
    save_uuids(UNIQUE_ID, query.replace("_", "."), OUTPUT, TAG)
    data = {
        "CPES": CPES,
        "Hostnames": Hostnames,
        "IP": IP,
        "Ports": Ports,
        "Tags": Tags,
        "Vulns": Vulns,
        "SC": SC,
        "RN": RN,
        "TXT": TXT,
        "HDRS": HDRS,
        "QUERY": query,
        "TAG": TAG,
        "DATE": str(datetime.now()),
    }
    data = json.dumps(data, indent=4)
    file_path = OUTPUT
    try:
        if path.exists(file_path):
            with open(file_path, "r", encoding="utf8") as file:
                try:
                    existing_data = json.load(file)
                except json.JSONDecodeError:
                    existing_data = []
            existing_data.append(data)

            with open(file_path, "w", encoding="utf8") as file:
                json.dump(existing_data, file, indent=4)
        else:
            with open(file_path, "w", encoding="utf8") as file:
                json.dump(data, file, indent=4)
        return True, None
    except Exception as err:
        return False, err


def save_shodan_output(QUERY, JSON_DATA, TAG="search"):
    global OUTPUT, query, err
    query = str(QUERY)
    xquery = str(QUERY).replace(":", "_")
    err = None
    UNIQUE_ID = uuid4()
    if UNIQUE_ID not in UNIQUE_IDS:
        UNIQUE_IDS.append(UNIQUE_ID)
    else:
        UNIQUE_ID = uuid4()
        UNIQUE_IDS.append(UNIQUE_ID)
    OUTPUT = path.join(
        OUTPUT_SEARCH_FOLDER,
        str(UNIQUE_ID) + "_" + str(xquery) + "_" + str(TAG) + ".json",
    )
    save_uuids(UNIQUE_ID, query, OUTPUT, TAG)
    data = {
        "JSON_DATA": JSON_DATA,
        "QUERY": query,
        "TAG": TAG,
        "DATE": str(datetime.now()),
    }
    data = json.dumps(data, indent=4)
    file_path = (
        OUTPUT.replace(" ", "_")
        .replace("\n", "_")
        .replace("\r", "_")
        .replace("'", "_")
        .replace('"', "_")
    )
    try:
        if path.exists(file_path) and path.isfile(file_path):
            with open(file_path, "r", encoding="utf8") as file:
                try:
                    existing_data = json.load(file)
                except json.JSONDecodeError:
                    existing_data = []
            existing_data.append(data)

            with open(file_path, "w", encoding="utf8") as file:
                json.dump(existing_data, file, indent=4)
        else:
            with open(file_path, "w", encoding="utf8") as file:
                json.dump(data, file, indent=4)
        return True, None
    except Exception as err:
        return False, err


def idbsearch(Host):
    global CPES, Hostnames, IP, Ports, Tags, Vulns, SC, RN, TXT, HDRS
    CPES = []
    Hostnames = []
    IP = []
    Ports = []
    Tags = []
    Vulns = []
    SC = []
    RN = []
    TXT = []
    HDRS = []
    url = IDB_URL + str(Host)
    try:
        headers = {"accept": "application/json"}
        resp = requests.get(url, timeout=30, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            CPES = data["cpes"]
            Hostnames = data["hostnames"]
            IP = data["ip"]
            Ports = data["ports"]
            Tags = data["tags"]
            Vulns = data["vulns"]
            SC = resp.status_code
            RN = resp.reason
            TXT = resp.text
            HDRS = resp.headers
            return CPES, Hostnames, IP, Ports, Tags, Vulns, SC, RN, TXT, HDRS
        else:
            SC = resp.status_code
            RN = resp.reason
            TXT = resp.text
            HDRS = resp.headers
            return CPES, Hostnames, IP, Ports, Tags, Vulns, SC, RN, TXT, HDRS
    except Exception as e:
        render_template("500.html", error=str(e))
    except KeyboardInterrupt:
        render_template("500.html", error="Keyboard Interrupt.")


def shdoan_scan(IPS, QUERY, INQUIRE, PAGE_LIMIT):
    global JSON_DATA, T_IPS, query
    T_IPS = []
    JSON_DATA = []
    limit = 10
    count = 1
    query = str(QUERY)
    page_limit = int(PAGE_LIMIT)
    inquire = bool(INQUIRE)

    api = shodan.Shodan(SHODAN_API_KEY)
    limit = limit * int(page_limit)
    try:
        if inquire == True:
            for banner in api.search_cursor(query):
                _ports = []
                hostinfo = api.host(banner["ip_str"])
                ip = banner["ip_str"]
                IPS.append(ip)
                for port in hostinfo["ports"]:
                    _ports.append(str(port))

                JSON_DATA.append(
                    {
                        "ip": banner["ip_str"],
                        "port": _ports,
                        "org": banner["org"],
                        "location": banner["location"],
                        "transport": banner["transport"],
                        "domains": banner["domains"],
                        "hostnames": banner["hostnames"],
                        "data": banner["data"],
                    }
                )

                count += 1
                if count >= limit + 1:
                    break
            JSON_DATA = dict(enumerate(JSON_DATA))
            success, err = save_shodan_output(query, JSON_DATA, TAG="search")
            if not success:
                return JSON_DATA
            else:
                error = str(err)
                return render_template("500.html", error=error)
        else:
            for banner in api.search_cursor(query):
                _ports = []
                ip = banner["ip_str"]
                IPS.append(ip)

                count += 1
                if count >= limit + 1:
                    break
            T_IPS = list(set(IPS))
            JSON_DATA = dict(enumerate(T_IPS))
            success, err = save_shodan_output(query, JSON_DATA, TAG="search")
            if not success:
                for ip in IPS:
                    if ip not in T_IPS:
                        T_IPS.append(ip)
                return T_IPS
            else:
                error = str(err)
                return render_template("500.html", error=error)
    except shodan.APIError as e:
        return render_template("500.html", error=str(e))
    except Exception as e:
        error = str(e)
        render_template("500.html", error=str(e))
    except KeyboardInterrupt:
        render_template("500.html", error="Keyboard Interrupt.")


def ips_from_json(json_data, XIPS=None):
    if XIPS is None:
        XIPS = []

    if isinstance(json_data, dict):
        for value in json_data.values():
            if isinstance(value, str) and is_valid_ip(value):
                XIPS.append(value)
            elif isinstance(value, (dict, list)):
                ips_from_json(value, XIPS)
    elif isinstance(json_data, list):
        for item in json_data:
            ips_from_json(item, XIPS)

    return XIPS


def is_valid_ip(ip):
    parts = ip.split(".")
    if len(parts) == 4:
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
    return False


def check4Tools():
    global IsNmap, IsNaabu, IsRustscan, XTOOLS
    IsNmap = False
    IsNaabu = False
    IsRustscan = False
    XTOOLS = []
    rtools = ["nmap", "naabu", "rustscan"]
    btool = ["builtin"]
    try:
        for tool in rtools:
            if platform == "win32":
                try:
                    cmd = f"{tool} --help"
                    if check_output(cmd):
                        if tool == "nmap":
                            IsNmap = True
                        elif tool == "naabu":
                            IsNaabu = True
                        elif tool == "rustscan":
                            IsRustscan = True
                        else:
                            pass
                except FileNotFoundError:
                    pass
            elif platform == "linux" or platform == "linux2":
                cmd = split("which " + str(tool))
            else:
                cmd = split("which " + str(tool))
            proc = run(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True)
            if proc.returncode == 0:
                if tool == "nmap":
                    IsNmap = True
                elif tool == "naabu":
                    IsNaabu = True
                elif tool == "rustscan":
                    IsRustscan = True
                else:
                    pass
            else:
                pass
        return (IsNmap, IsNaabu, IsRustscan)
    except Exception as e:
        error = str(e)
        return render_template("500.html", error=error)
    except KeyboardInterrupt:
        console.print("[bold red]Keyboard Interrupt.[/bold red]", style="blink")
        exit(0)


def nmapScan(host):
    try:
        nmap = nmap3.Nmap()
        results = nmap.scan_top_ports(host, args="-sV -sC -Pn -T4")
        return results
    except Exception as e:
        error = str(e)
        return render_template("500.html", error=error)
    except KeyboardInterrupt:
        console.print("[bold red]Keyboard Interrupt.[/bold red]", style="blink")
        exit(0)


####################
#   WebApp Routes  #
####################
# 404 page route
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


# Check WHITE_LIST_ENDPOINTS before each request
# @app.before_request
# def before_request():
#     if request.endpoint not in WHITE_LIST_ENDPOINTS:
#         return render_template("403.html")


@app.route("/", methods=["GET"])
@app.route("/home", methods=["GET"])
@app.route("/index", methods=["GET"])
def index():
    if request.method == "GET":
        error = None
        try:
            html_content = open(README, "r", encoding="utf-8").read()
            html_content = Markdown().convert(html_content)
            return render_template("index.html", user=str(USER), content=html_content)
        except Exception as e:
            error = str(e)
            return render_template("500.html", error=error)

    else:
        return render_template("403.html")


@app.route("/search", methods=["GET", "POST"])
def search():
    if request.method == "POST":
        global QUERY, COUNTRY, INQUIRE, PLIMIT
        QUERY = None
        COUNTRY = None
        INQUIRE = False
        PLIMIT = None
        immutable_dict = request.form
        dic = immutable_dict.to_dict()
        for key, value in dic.items():
            if key == "query" and value != "":
                QUERY = value
            elif key == "country" and value != "":
                COUNTRY = value
            elif key == "inquire" and value != "":
                if value == "on":
                    INQUIRE = True
                else:
                    INQUIRE = False
            elif key == "page_limit" and value != "":
                PLIMIT = int(value)
            else:
                pass
        if COUNTRY != None:
            QUERY = QUERY + " country:" + str(COUNTRY)
        else:
            QUERY = QUERY
        if QUERY != None and PLIMIT != None:
            shdoan_scan(IPS, QUERY, INQUIRE, PLIMIT)
            if INQUIRE:
                return render_template(
                    "results.html", data=JSON_DATA, jdata=None, uinput=QUERY
                )
            else:
                ips = []
                for ip in T_IPS:
                    if ip not in ips:
                        ips.append(ip)
                return render_template(
                    "results.html", jdata=ips, data=None, uinput=QUERY
                )
        else:
            error = "Query and Page Limit cannot be empty."
            return render_template("500.html", error=error)
    elif request.method == "GET":
        if not path.exists(ENV_FILE):
            return redirect(url_for("config"))
        else:
            return render_template("search.html")
    else:
        return render_template("403.html")


@app.route("/internetDB", methods=["GET", "POST"])
def idbSearch():
    if request.method == "POST":
        global IP, QUERY
        IP = None
        QUERY = None
        immutable_dict = request.form
        dic = immutable_dict.to_dict()
        if dic["ip_address"] != "":
            QUERY = (
                str(dic["ip_address"])
                .replace(" ", "_")
                .replace("\n", "_")
                .replace("\r", "_")
                .replace("\t", "_")
                .replace("\v", "_")
                .replace(".", "_")
            )
            IP = str(dic["ip_address"])
            idbsearch(IP)
            success, err = save_idb_output(
                str(QUERY),
                str(CPES),
                str(Hostnames),
                str(Ports),
                str(Tags),
                str(Vulns),
                str(SC),
                str(RN),
                str(TXT),
                str(HDRS),
                TAG="idb",
            )
            if success:
                return render_template(
                    "idbResults.html",
                    cpes=CPES,
                    hostnames=Hostnames,
                    ip=IP,
                    ports=Ports,
                    tags=Tags,
                    vulns=Vulns,
                    sc=SC,
                    rn=RN,
                    txt=TXT,
                    hdrs=HDRS,
                )
            else:
                error = str(err)
                return render_template("500.html", error=error)
        else:
            return render_template(
                "idbResults.html",
                cpes=None,
                hostnames=None,
                ip=None,
                ports=None,
                tags=None,
                vulns=None,
                sc=None,
                rn=None,
                txt=None,
                hdrs=None,
            )
    elif request.method == "GET":
        return render_template("internetDB.html")
    else:
        return render_template("403.html")


@app.route("/history", methods=["GET", "POST"])
def history():
    if request.method == "GET":
        search_history_data = load_search_history_data()
        #  Show latest search results first
        if search_history_data != None:
            search_history_data = dict(reversed(list(search_history_data.items())))
        return render_template("history.html", search_results=search_history_data)
    elif request.method == "POST":
        search_query = request.form.get("search", "").lower()
        search_history_data = load_search_history_data()
        filtered_results = {}
        for key, value in search_history_data.items():
            if (
                search_query in value["date"]
                or search_query in value["query"]
                or search_query in value["tag"]
            ):
                filtered_results[key] = value
        return render_template("history.html", search_results=filtered_results)
    else:
        return render_template("403.html")


@app.route("/more_info/<key>", methods=["GET"])
def more_info(key):
    search_folder = OUTPUT_SEARCH_FOLDER
    idb_folder = IDB_SEARCH_FOLDER
    key = str(key)
    FILE = None
    output_data = None

    for file in listdir(search_folder):
        if key in file:
            FILE = str(path.join(search_folder, file))

    for file in listdir(idb_folder):
        if key in file:
            FILE = str(path.join(idb_folder, file))

    if FILE != None:
        with open(FILE, "r", encoding="utf8") as handler:
            output_data = json.load(handler)
            output_data = json.loads(output_data)
        output_data = json.dumps(output_data, indent=4, sort_keys=True)
        return render_template("more_info.html", data=output_data)
    else:
        return render_template("403.html")


@app.route("/dorks", methods=["GET"])
def dorks():
    if request.method == "GET":
        error = None
        try:
            with open(DORKS, "r", encoding="utf8") as file:
                file_content = file.read()

            sections = re.split(r"^#", file_content, flags=re.MULTILINE)[1:]
            data = {}
            for section in sections:
                lines = section.strip().split("\n")
                heading = lines[0].strip()
                content = [line.strip() for line in lines[1:]]
                data[heading] = content
            return render_template("Dorks.html", data=data)
        except Exception as e:
            error = str(e)
            return render_template("500.html", error=error)

    else:
        return render_template("403.html")


@app.route("/about", methods=["GET"])
def about():
    if request.method == "GET":
        error = None
        try:
            with open(ABOUT, "r", encoding="utf8") as file:
                file_content = file.read()
            html_content = Markdown().convert(file_content)
            return render_template("about.html", content=html_content)
        except Exception as e:
            error = str(e)
            return render_template("500.html", error=error)
    else:
        return render_template("403.html")


@app.route("/config", methods=["GET", "POST"])
def config():
    if request.method == "GET":
        message = None
        error = None
        try:
            with open(ENV_FILE, "r", encoding="utf8") as file:
                load_dotenv()
                SHODAN_API_KEY = str(getenv("SHODAN_API_KEY"))
                data = SHODAN_API_KEY[:4] + "..." + SHODAN_API_KEY[-8:]
                message = "Shodan API Key is already set."
            return render_template("config.html", data=data, message=message)
        except FileNotFoundError:
            error = ".env file not found. Config File is not found. Please create a .env file and set the Shodan API Key."
            data = None
            return render_template("config.html", data=data, error=error)
        except Exception as e:
            error = str(e)
            return render_template("500.html", error=error)
    elif request.method == "POST":
        message = None
        error = None
        try:
            immutable_dict = request.form
            dic = immutable_dict.to_dict()
            for key, value in dic.items():
                if key == "shodan_api_key" and value != "":
                    SHODAN_API_INFO = "https://api.shodan.io/api-info?key=" + str(value)
                    resp = requests.get(SHODAN_API_INFO)
                    if resp.status_code == 200:
                        with open(ENV_FILE, "w", encoding="utf8") as file:
                            file.write("SHODAN_API_KEY=" + str(value))

                        message = "Shodan API Key is valid and Set."
                        return redirect(url_for("index"))
                    else:
                        error = "Invalid Shodan API Key."
                        return render_template("config.html", data=data, error=error)
                else:
                    pass
        except Exception as e:
            error = str(e)
            return render_template("500.html", error=error)
    else:
        return render_template("403.html")


@app.route("/enum/<key>", methods=["GET"])
def enumeration(key):
    if request.method == "GET":
        search_folder = OUTPUT_SEARCH_FOLDER
        idb_folder = IDB_SEARCH_FOLDER
        enum_folder = ENUM_FOLDER
        key = str(key)
        FILE = None
        output_data = None
        scan_type = None
        _ip_ = None
        xQuery = None
        XIPS = []

        for FILE in listdir(enum_folder):
            if key in FILE:
                FILE = str(path.join(enum_folder, FILE))
                scan_type = "enum"

        for file in listdir(search_folder):
            if key in file:
                FILE = str(path.join(search_folder, file))
                scan_type = "search"

        for file in listdir(idb_folder):
            if key in file:
                FILE = str(path.join(idb_folder, file))
                scan_type = "idb"

        if path.exists(FILE) and path.isfile(FILE):
            if FILE != None:
                with open(FILE, "r", encoding="utf8") as handler:
                    output_data = json.load(handler)
                    output_data = json.loads(output_data)
                    xQuery = output_data["QUERY"]
                if scan_type == "idb":
                    _ip_ = output_data["IP"]
                output_data = ips_from_json(output_data, XIPS)
                return render_template(
                    "enumeration.html",
                    data=output_data,
                    scan_type=scan_type,
                    ip=_ip_,
                    query=xQuery,
                )
            else:
                output_data = "No Data Found."
                return render_template(
                    "enumeration.html",
                    data=output_data,
                    scan_type=scan_type,
                    ip=_ip_,
                    query=xQuery,
                )
        else:
            error = "File Not Found."
            return render_template("500.html", error=error)
    else:
        return render_template("403.html")


######################
#     API Routes     #
######################
@app.route("/api/enum/<host>", methods=["GET"])
def ip_enumeration(host):
    if request.method == "GET":
        global JDATA
        JDATA = []
        error = None
        enum_folder = ENUM_FOLDER
        try:
            ip = str(host)
            out_file = path.join(enum_folder, ip + ".json")
            if path.exists(out_file) and path.isfile(out_file):
                with open(out_file, "r", encoding="utf8") as file:
                    JDATA = json.loads(file.read())
                    return JDATA
            else:
                ip_type = IpType(ip).get_ip_type()
                reverse_dns = ReverseDNS(ip).get_reverse_dns()
                dns_lookup = DnsLookup(ip).get_dns()
                whois = Whois(ip).get_whois()
                geo_location = GeoLocation(ip).get_geo_location()
                ip2asn = Ip2ASN(ip).get_asn()
                JDATA = {
                    "status": "Success",
                    "ip": ip,
                    "ip_type": ip_type,
                    "reverse_dns": reverse_dns,
                    "dns_lookup": dns_lookup,
                    "whois": whois,
                    "geo_location": geo_location,
                    "ip2asn": ip2asn,
                }
                if path.exists(out_file) and path.isfile(out_file):
                    pass
                else:
                    with open(out_file, "w", encoding="utf8") as file:
                        json.dump(JDATA, file, indent=4, sort_keys=True, default=str)

                return JDATA
        except Exception as e:
            error = str(e)
            return render_template("500.html", error=error)
    else:
        return render_template("403.html")


@app.route("/api/portscan/<path:combined>", methods=["GET"])
def portscan(combined):
    if request.method == "GET":
        global JDATA
        JDATA = []
        error = None
        pscan_folder = PSCAN_Folder
        if check4Tools():
            host, tool = combined.split("&")
        try:
            JDATA = {
                "status": "Success",
                "host": host,
                "tool": tool,
                "nmap": IsNmap,
                "naabu": IsNaabu,
                "rustscan": IsRustscan,
            }
            return JDATA
        except Exception as e:
            error = str(e)
            return render_template("500.html", error=error)
    else:
        return render_template("403.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
