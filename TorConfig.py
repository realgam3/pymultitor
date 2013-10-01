########################################################
__author__ = 'RealGame (Tomer Zait)'
__license__ = 'GPL v3'
__version__ = '1.0.0'
__email__ = 'realgam3@gmail.com'
########################################################

from os import getcwd, path
from sys import platform
from requesocks.defaults import defaults
from ConfigParser import ConfigParser


def isWindows():
    return platform == 'win32'


def isMacosx():
    return platform == 'darwin'


class BasicConfiguration(object):
    def __init__(self):
        self.__CONFIG_PATH = path.join(getcwd(), 'torCfg.conf')
        self.TOR_ROOT_DATA_PATH = path.join(getcwd(), 'torData')
        self.TOR_TIMEOUT = 10
        self.PROCESS_TIMEOUT = 120
        self.HOST = '127.0.0.1'
        self.HEADERS = {'User-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0'}

        self.__config()

    def __config(self):
        # Create Tor Command For Linux / Windows / MacOSX
        self.TOR_CMD = 'tor'
        if isWindows():
            self.TOR_CMD = path.join(self.TOR_ROOT_DATA_PATH, self.TOR_CMD + '.exe')
        elif isMacosx():
            self.TOR_CMD = path.join('/usr/local/bin', self.TOR_CMD)

        #Read Configuration
        torCfg = ConfigParser()
        if not path.exists(self.__CONFIG_PATH):
            basic_config = "[parameters]\n"
            basic_config += "PASS_PHRASE = multitor\n"
            basic_config += "MAX_NUM_OF_THREADS = 4\n"
            basic_config += "REQUEST_TIMEOUT = 15\n"
            basic_config += "MAX_RETRIES = 2\n"
            basic_config += "CONTROL_START_PORT = 9050\n"
            basic_config += "SOCKS_START_PORT = 5050\n"
            basic_config += "START = 1\n"
            basic_config += "END = 400\n"
            basic_config += "INC = 50\n"

            open(self.__CONFIG_PATH, "w").write(basic_config)

        torCfg.read(self.__CONFIG_PATH)

        #Configure Globals
        self.MAX_NUM_OF_THREADS = torCfg.getint("parameters", "MAX_NUM_OF_THREADS")
        self.REQUEST_TIMEOUT = torCfg.getint("parameters", "REQUEST_TIMEOUT")
        self.MAX_RETRIES = torCfg.getint("parameters", "MAX_RETRIES")
        self.CONTROL_START_PORT = torCfg.getint("parameters", "CONTROL_START_PORT")
        self.SOCKS_START_PORT = torCfg.getint("parameters", "SOCKS_START_PORT")
        self.PASS_PHRASE = torCfg.get("parameters", "PASS_PHRASE")
        self.START = torCfg.getint("parameters", "START")
        self.END = torCfg.getint("parameters", "END")
        self.INC = torCfg.getint("parameters", "INC")

        # Change Requesocks Default Configurations
        defaults['pool_connections'] = self.MAX_NUM_OF_THREADS
        defaults['pool_maxsize'] = self.MAX_NUM_OF_THREADS
        defaults['max_retries'] = self.MAX_RETRIES
        defaults['max_redirects'] = 2