## Overview

Python Multi Threaded Tor Proxy,  
Did you ever want to be at two different places at the same time?  
When I asked myself this question, I actually started developing this solution in my mind.  
While performing penetration tests there are often problems caused by security devices that block the "attacking" IP.  
This really annoyed me, so I wrote a script to supply a solution for this problem.  
With a large number of IP addresses performing the attacks, better results are guaranteed - especially when attempting attacks to bypass Web Application Firewalls, Brute-Force type attacks and many more.  

[Blackhat Asia] https://www.blackhat.com/asia-17/arsenal.html#pymultitor  
[Owasp-IL Presentation] https://www.owasp.org/images/3/3d/OWASPIL-2016-02-02_PyMultiTor_TomerZait.pdf  
[DigitalWhisper Article (Hebrew)] http://www.digitalwhisper.co.il/files/Zines/0x2E/DW46-3-PyMultitor.pdf  

## Installation

### Prerequisites

* Python 2.7+.
* A C compiler, Python headers, etc. (are needed to compile several dependencies).
  * On Ubuntu, `sudo apt-get install -y build-essential libssl-dev python-setuptools python-pip python-wheel python-dev`
  * On Fedora, `sudo dnf install -y redhat-rpm-config gcc gcc-c++ make openssl-devel python-setuptools python-pip python-wheel python-devel`
  * On Windows, install http://aka.ms/vcpython27
  * On MacOS,
    * install xcode command line tools: `xcode-select --install`
    * install homebrew(brew): `$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"`
* mitmproxy dependencies.
  * On Ubuntu, `sudo apt-get install -y libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg8-dev zlib1g-dev`
  * On Fedora, `sudo dnf install -y libffi-devel openssl-devel libxml2-devel libxslt-devel libpng-devel libjpeg-devel`
  * On Windows,
    * download lxml: http://www.lfd.uci.edu/~gohlke/pythonlibs/#lxml
    * install lxml: `pip install lxml-*-cp27-cp27m-win*.whl`
  * On MacOS, `brew install mitmproxy`
* tor.
  * On Ubuntu, `sudo apt-get install -y tor`
  * On Fedora, `sudo dnf install -y tor`
  * On Windows,
    * download tor expert bundle: https://www.torproject.org/download/download.html.en
    * insert tor to your path environment: `{tor-win32-*_path}\Tor`
    * if you don't know how remember tor.exe path and use `--tor-cmd` argument on pymultitor (for example: `pymultitor --tor-cmd "c:\Pentest\Web\tor-win32-0.2.9.9\Tor\tor.exe"`)
  * On MacOS, `brew install tor`
  
### From pip

```sh
pip install pymultitor
# On MacOs (it's Easier To Use Python 3):
# pip3 install pymultitor
```

You may need to use `sudo`, depending on your Python installation.

### From Source

```sh
git clone https://github.com/realgam3/pymultitor.git
cd pymultitor

# Install python dependencies.
# Depending on your setup, one or both of these may require sudo.
pip install -r requirements.txt
python setup.py install

# On MacOs (it's Easier To Use Python 3):
# pip3 install -r requirements.txt
# python3 setup.py install

# Confirm that everything works
pymultitor --help
```

Bug reports on installation issues are welcome!

## Usage

### Basic Usage

1. Run `pymultitor --on-string "Your IP Address Blocked"`.  
2. On your script use proxy (`http://127.0.0.1:8080`).  
   When the string `Your IP Address Blocked` will present in the response content, you will exit from another IP address.  

### Command Line Flags

See `--help` for the complete list, but in short:

```sh
Usage: pymultitor [-h] [-v] [-lh LISTEN_HOST] [-lp LISTEN_PORT] [-s] [-i] [-d]
                  [-p PROCESSES] [-c CMD] [--on-count ON_COUNT]
                  [--on-string ON_STRING] [--on-regex ON_REGEX] [--on-rst]

# When To Change IP Address
--on-count    Change IP Every x Requests (Resources Also Counted).
--on-string   Change IP When String Found On The Response Content.
--on-regex    Change IP When Regex Found On The Response Content.
--on-rst      Change IP When Connection Closed With TCP RST.
```
