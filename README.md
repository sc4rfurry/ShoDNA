[![forthebadge made-with-python](https://ForTheBadge.com/images/badges/made-with-python.svg)](https://www.python.org/)



##
# ShoDNA (◣_◢)ノ-=≡≡卍
Yet Another Shodan CLI Scanner with addition of DORKs related to shodan.

## Table of Contents
- [ShoDNA (◣_◢)ノ-=≡≡卍]
    - [Technologies & Tools](#technologies--tools)
    - [Requirements](#requirements)
    - [Features](#features)
    - [Installation](#installation)
    - [Config](#config)
    - [Usage](#usage)
        - [Options](#options)
        - [Example](#example)
    - [Todo](#todo)
    - [Contributing](#contributing)
    - [License](#license)

#

### 🔧 Technologies & Tools

![](https://img.shields.io/badge/OS-Linux-informational?style=flat-square&logo=ubuntu&logoColor=white&color=5194f0&bgcolor=110d17)
![](https://img.shields.io/badge/Editor-VS_Code-informational?style=flat-square&logo=visual-studio&logoColor=white&color=5194f0)
![](https://img.shields.io/badge/Language-python-informational?style=flat-square&logo=python&logoColor=white&color=5194f0&bgcolor=110d17)
![](https://img.shields.io/badge/Python_Version-3.10-informational?style=flat-square&logo=python&logoColor=white&color=5194f0&bgcolor=110d17)

##

### 📚 Requirements
> - Python 3.9+
> - pip3

### Features
- Quick and easy to use
- Search the Custom Quries
- Pre-Included **`Dorks`**
- Setch `Shodan's API` Information.

> `Note:` Please keep in mind that the tool is still in development and more features will be added in the future.


## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the requirements.
if not installed, install it using the following command.
```bash
sudo apt-get install python3-pip
```

> It is advised to install the python requirements in a virtual environment, for that install the venv package.

```bash
    python3 -m pip install venv
    python3 -m venv env
    source env/bin/activate
```

After that run the following commands:
```bash
    python3 -m pip install -r requirements.txt
```
#

## Config
> `ShoDNA` by default uses **Shodan's API** and need the API key, for that make sure you have a `.env` file in the program folder with the API key as follow:
```bash
SHODAN_API_KEY=abc123ShodanKeyHere
```
#

## Usage

```bash
python3 main.py -q [Query]
```

#### Options

```bash
        -q              Shodan Query
        -pl             Page Liimit (Defaulr: 1)
        -cn             Specify the Country (US,JP,FR)
        -iq             Fetch More Information about each Host (Hostname, Ports etc)
        -lq             Show the Pre-Included SHodan Dorks (Scada, Medical etc)
        -ai             Fetch API Information (API key Required)
        -idb            Fetch the results using the OpenAPI by Shodan
        -h              Print the help menu
```

##

# (◣_◢) WebUI - ShoDNA

To run the Web Server you have to install the requirements for the Web Server too.

```bash
cd shodna/web
python3 -m pip install -r requirements.txt
```

For `Development` run the server as following:

```bash
python3 app.py
```

As for the `Production` Server do the following:

```bash
cd shodna/web
python3 -m pip install -r requirements.txt
gunicorn -c config.py app:app;
```
+ `gunicorn` should be installed.

##

## Json Viewer
- For now history is json form, so for Chrome user's Kindly install the following extention

```console
> https://chrome.google.com/webstore/detail/json-viewer-pro/eifflpmocdbdmepbjaopkkhbfmdgijcc
```

#### Example
```bash
1) python3 main.py -q 'apache' -pl 2 -cn 'US' -iq
2) python3 main.py -lq
2) python3 main.py -ai
3) python3 main.py -idb 1.1.1.1
4) python3 main.py -h
```


### Todo
- [ ] More things to add
- [ ] Overall Optimizations
- [X] WebUI (Completed)
- [X] Bug Fixes (I tried :/)

#

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)