########################################################
__author__ = 'RealGame (Tomer Zait)'
__license__ = 'GPL v3'
__version__ = '1.0.0'
__email__ = 'realgam3@gmail.com'
########################################################

from gevent.pool import Pool
from os import getcwd, path
from sys import platform
from requesocks.defaults import defaults


def isWindows():
    return platform == 'win32'


def isMacosx():
    return platform == 'darwin'


#Define Configuration Variables:
TOR_ROOT_DATA_PATH = path.join(getcwd(), 'torData')

# Create Tor Command For Linux / Windows / MacOSX
TOR_CMD = 'tor'
if isWindows():
    TOR_CMD = path.join(TOR_ROOT_DATA_PATH, TOR_CMD + '.exe')
elif isMacosx():
    TOR_CMD = path.join('/usr/local/bin', TOR_CMD)

MAX_NUM_OF_THREADS = 4
TOR_TIMEOUT = 10
PROCESS_TIMEOUT = 120
REQUEST_TIMEOUT = 15
MAX_RETRIES = 2
CONTROL_START_PORT = 9050
SOCKS_START_PORT = 5050
PASS_PHRASE = 'lol'
HOST = '127.0.0.1'
POOL = Pool(size=MAX_NUM_OF_THREADS)
HEADERS = {'User-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0'}
START = 1
END = 400
INC = 50
# Change Requesocks Default Configurations
defaults['pool_connections'] = MAX_NUM_OF_THREADS
defaults['pool_maxsize'] = MAX_NUM_OF_THREADS
defaults['max_retries'] = MAX_RETRIES
defaults['max_redirects'] = 2
