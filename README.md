## PyMultiTor

[![PyPI version](https://img.shields.io/pypi/v/pymultitor)](https://pypi.org/project/pymultitor/)
[![Downloads](https://pepy.tech/badge/pymultitor)](https://pepy.tech/project/pymultitor)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pymultitor)  

Python Multi Threaded Tor Proxy,  
Did you ever want to be at two different places at the same time?  
When I asked myself this question, I actually started developing this solution in my mind.  
While performing penetration tests there are often problems caused by security devices that block the "attacking" IP.  
This really annoyed me, so I wrote a script to supply a solution for this problem.  
With a large number of IP addresses performing the attacks, better results are guaranteed - especially when attempting
attacks to bypass Web Application Firewalls, Brute-Force type attacks and many more.

[Blackhat Asia] https://www.blackhat.com/asia-17/arsenal.html#pymultitor  
[Owasp-IL Presentation] https://www.owasp.org/images/3/3d/OWASPIL-2016-02-02_PyMultiTor_TomerZait.pdf  
[DigitalWhisper Article (Hebrew)] http://www.digitalwhisper.co.il/files/Zines/0x2E/DW46-3-PyMultitor.pdf

![Logo](https://raw.githubusercontent.com/realgam3/pymultitor/master/assets/img/pymultitor-logo.png)

## Installation

### Prerequisites

* Python 3.10+.
* mitmproxy (https://mitmproxy.org/).
* tor.
    * On Ubuntu / Kali, `sudo apt install -y tor`
    * On Centos, `sudo yum install -y tor`
    * On Fedora, `sudo dnf install -y tor`
    * On Windows,
        * download tor expert bundle: https://www.torproject.org/download/tor/
        * insert tor to your path environment: `{tor-win32-*_path}\Tor`
        * if you don't know how remember tor.exe path and use `--tor-cmd` argument on pymultitor (for
          example: `pymultitor --tor-cmd "c:\Pentest\Web\tor-win32-0.2.9.9\Tor\tor.exe"`)
    * On MacOS, `brew install tor`

### From pip

```shell
pip3 install pymultitor
```

### From Docker

```shell
docker pull realgam3/pymultitor
```

### From Source

```shell
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

### Docker Usage

1. Run `docker run --rm -p 8080:8080 realgam3/pymultitor --on-string "Your IP Address Blocked"`.  
2. On your script use proxy (`http://127.0.0.1:8080`).  
   When the string `Your IP Address Blocked` will present in the response content, you will exit from another IP address.  

### API Usage

PyMultiTor provides a REST API for managing proxy identities. You can use the API to change your proxy identity on demand.

#### Authentication

The API requires authentication using a Bearer token. You can set the token in two ways:

1. **Environment Variable**: Set the `PYMULTITOR_TOKEN` environment variable:
   ```bash
   export PYMULTITOR_TOKEN="your-secret-token-here"
   ```
   **Note**: If `PYMULTITOR_TOKEN` is not set, PyMultiTor will automatically generate a random token for you.

2. **Command Line**: starting PyMultiTor:
   ```bash
   pymultitor"
   ```

#### Endpoints

**Change Identity**
- **URL**: `/identity`
- **Method**: `POST`

**Example Usage**:
```bash
curl http://pymultitor/identity -X POST \
  --header "Proxy-Authorization: Bearer {Token}" \
  --proxy http://localhost:8080
```

**Status**
- **URL**: `/status`
- **Method**: `GET`

**Example Usage**:
```bash
curl http://pymultitor/status \
  --header "Proxy-Authorization: Bearer {Token}" \
  --proxy http://localhost:8080
```

**Note**: Replace `{Token}` with your actual authentication token.

### Command Line Arguments

```shell
pymultitor --help
```

```text
usage: pymultitor.py [-h] [-v] [-lh LISTEN_HOST] [-lp LISTEN_PORT] [-s] [-a AUTH] [-i] [-d] [-p PROCESSES] [-c CMD] [-e CONFIG] [-t TIMEOUT] [-r TRIES]
                     [--request-timeout REQUEST_TIMEOUT] [--on-count ON_COUNT] [--on-string ON_STRING] [--on-regex ON_REGEX] [--on-rst] [--on-status-code [ON_STATUS_CODE ...]]
                     [--on-timeout]

options:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -lh, --host LISTEN_HOST
                        proxy listen host. (default: 127.0.0.1)
  -lp, --port LISTEN_PORT
                        proxy listen port (default: 8080)
  -s, --socks           use as socks proxy (not http proxy) (default: False)
  -a, --auth AUTH       set proxy authentication (format: 'username:pass') (default: )
  -i, --insecure        insecure ssl (default: False)
  -d, --debug           Debug Log. (default: False)
  -p, --tor-processes PROCESSES
                        number of tor processes in the cycle (default: 2)
  -c, --tor-cmd CMD     tor cmd (executable path + arguments) (default: tor)
  -e, --tor-config CONFIG
                        tor extended json configuration (default: {})
  -t, --tor-timeout TIMEOUT
                        timeout in seconds for starting a tor instance; 0 disables timeout (default: 90)
  -r, --tor-tries TRIES
                        number tries to start a tor instance before it fails (default: 5)
  --request-timeout REQUEST_TIMEOUT
                        timeout in seconds for http requests; 0 disables timeout (default: 0)
  --on-count ON_COUNT   change ip every x requests (resources also counted) (default: 0)
  --on-string ON_STRING
                        change ip when string found in the response content (default: )
  --on-regex ON_REGEX   change ip when regex found in The response content (default: )
  --on-rst              change ip when connection closed with tcp rst (default: False)
  --on-status-code [ON_STATUS_CODE ...]
                        change ip when one of the specified status codes is returned (default: [])
  --on-timeout          change ip when request times out (default: False)
```
