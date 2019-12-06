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

* Python 3.6+.
* mitmproxy (https://mitmproxy.com/).
* tor.
  * On Ubuntu / Kali, `sudo apt install -y tor`
  * On Centos, `sudo yum install -y tor`
  * On Fedora, `sudo dnf install -y tor`
  * On Windows,
    * download tor expert bundle: https://www.torproject.org/download/tor/
    * insert tor to your path environment: `{tor-win32-*_path}\Tor`
    * if you don't know how remember tor.exe path and use `--tor-cmd` argument on pymultitor (for example: `pymultitor --tor-cmd "c:\Pentest\Web\tor-win32-0.2.9.9\Tor\tor.exe"`)
  * On MacOS, `brew install tor`
  
### From pip

```sh
pip3 install pymultitor
```

You may need to use `sudo`, depending on your Python installation.

### From Source

```sh
git clone https://github.com/realgam3/pymultitor.git
cd pymultitor

# Install python dependencies.
# Depending on your setup, one or both of these may require sudo.
pip3 install -r requirements.txt
python3 setup.py install

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
