#!/usr/bin/env python

import re
import sys
import json
import atexit
import socket
import logging
import requests
import platform
import itertools
from os import path
from shutil import rmtree
from tempfile import mkdtemp
from multiprocessing.pool import ThreadPool
from stem.control import Controller, Signal
from requests.exceptions import ConnectionError
from stem.process import launch_tor_with_config
from mitmproxy.proxy import ProxyServer, ProxyConfig
from mitmproxy.options import Options as ProxyOptions
from mitmproxy.controller import handler as proxy_handler
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

# If mitmproxy > 0.18.3
websocket_key = 'websocket'
new_mitmproxy = hasattr(ProxyOptions(), websocket_key)
if new_mitmproxy:
    from mitmproxy.http import HTTPResponse
    from mitmproxy.master import Master
else:
    websocket_key = 'websockets'
    from mitmproxy.flow import State, FlowMaster as Master
    from mitmproxy.models import HTTPResponse

__version__ = '2.1.0'

logger = logging.getLogger(__name__)


def is_windows():
    return platform.system().lower() == 'windows'


class Tor(object):
    def __init__(self, cmd='tor'):
        self.logger = logging.getLogger(__name__)
        self.tor_cmd = cmd
        self.socks_port = self.free_port()
        self.control_port = self.free_port()
        self.data_directory = mkdtemp()
        self.id = self.socks_port
        self.process = None
        self.controller = None
        self.__is_shutdown = False

    def __del__(self):
        self.shutdown()

    def __enter__(self):
        return self.run()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

    def run(self):
        self.logger.debug("[%05d] Executing Tor Process" % self.id)
        self.process = launch_tor_with_config(
            config={
                "ControlPort": str(self.control_port),
                "SOCKSPort": str(self.socks_port),
                "DataDirectory": self.data_directory,
                "AllowSingleHopCircuits": "1",
                "ExcludeSingleHopRelays": "0",
            },
            tor_cmd=self.tor_cmd,
            init_msg_handler=self.print_bootstrapped_line
        )

        self.logger.debug("[%05d] Creating Tor Controller" % self.id)
        self.controller = Controller.from_port(port=self.control_port)
        self.controller.authenticate()

        return self

    def shutdown(self):
        if self.__is_shutdown:
            return

        self.__is_shutdown = True
        self.logger.debug("[%05d] Destroying Tor" % self.id)
        self.controller.close()
        self.process.terminate()
        self.process.wait()

        # If Not Closed Properly
        if path.exists(self.data_directory):
            rmtree(self.data_directory)

    def newnym_available(self):
        return self.controller.is_newnym_available()

    def newnym(self):
        if not self.newnym_available():
            self.logger.warning("[%05d] Cant Change Tor Identity (Need More Tor Processes)" % self.id)
            return False

        self.logger.debug("[%05d] Changing Tor Identity" % self.id)
        self.controller.signal(Signal.NEWNYM)
        return True

    def print_bootstrapped_line(self, line):
        if "Bootstrapped" in line:
            self.logger.debug("[%05d] Tor Bootstrapped Line: %s" % (self.id, line))

            if "100%" in line:
                self.logger.debug("[%05d] Tor Process Executed Successfully" % self.id)

    @staticmethod
    def free_port():
        """
        Determines a free port using sockets.
        Taken from selenium python.
        """
        free_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        free_socket.bind(('0.0.0.0', 0))
        free_socket.listen(5)
        port = free_socket.getsockname()[1]
        free_socket.close()
        return port


class MultiTor(object):
    def __init__(self, size=2, cmd='tor'):
        self.logger = logging.getLogger(__name__)
        self.cmd = cmd
        self.size = size
        self.list = []
        self.cycle = None
        self.current = None

    def run(self):
        self.logger.info("Executing %d Tor Processes" % self.size)

        # If OS Platform Is Windows Run Processes Async
        if is_windows():
            pool = ThreadPool(processes=self.size)
            self.list = pool.map(lambda _: Tor(cmd=self.cmd).run(), range(self.size))
        else:
            self.list = [Tor(cmd=self.cmd).run() for _ in range(self.size)]

        self.logger.info("All Tor Processes Executed Successfully")
        self.cycle = itertools.cycle(self.list)
        self.current = next(self.cycle)

    @property
    def proxy(self):
        proxy_url = 'socks5://127.0.0.1:%d' % self.current.socks_port
        return {'http': proxy_url, 'https': proxy_url}

    def new_identity(self):
        self.current.newnym()
        self.current = next(self.cycle)

        return self.proxy

    def shutdown(self):
        for tor in self.list:
            tor.shutdown()


class MultiTorProxy(Master):
    def __init__(self, listen_host="", listen_port=8080, socks=False, auth=None, insecure=False,
                 processes=2, cmd='tor',
                 on_count=0, on_string=None, on_regex=None, on_rst=False, on_callback=None):
        self.logger = logging.getLogger(__name__)

        # Change IP Policy (Configuration)
        self.counter = itertools.count(1)
        self.on_count = on_count
        self.on_regex = on_regex
        self.on_rst = on_rst

        self.on_string = on_string
        if self.on_string:
            # For Python 3
            self.on_string = str.encode(on_string)

        self.on_callback = None
        if callable(on_callback):
            self.on_callback = on_callback

        # Create MultiTor (Tor Pool)
        self.multitor = MultiTor(size=processes, cmd=cmd)

        # Create Proxy Server
        self.insecure = insecure

        options_dict = {
            'listen_host': listen_host,
            'listen_port': listen_port,
            'ssl_insecure': self.insecure,
            'mode': "socks5" if socks else "regular",
            'rawtcp': False,
            'auth_singleuser': auth
        }
        # options_dict['proxyauth' if new_mitmproxy else 'auth_singleuser'] = auth

        options = ProxyOptions(**options_dict)

        setattr(options, websocket_key, False)
        config = ProxyConfig(options)
        server = ProxyServer(config)

        if new_mitmproxy:
            super(self.__class__, self).__init__(options, server)
        else:
            state = State()
            super(self.__class__, self).__init__(options, server, state)

    def run(self):
        try:
            self.multitor.run()
            super(self.__class__, self).run()
        except KeyboardInterrupt:
            self.multitor.shutdown()
            self.shutdown()

    def create_response(self, request):
        response = requests.request(
            method=request.method,
            url=request.url,
            data=request.content,
            headers=request.headers,
            allow_redirects=False,
            verify=not self.insecure,
            proxies=self.multitor.proxy
        )

        response_headers = dict(response.headers)
        if not new_mitmproxy:
            response_headers = response.headers.items()

        return HTTPResponse.make(
            status_code=response.status_code,
            content=response.content,
            headers=response_headers,
        )

    @proxy_handler
    def request(self, flow):
        error = None
        try:
            flow.response = self.create_response(flow.request)
        except ConnectionError as error:
            # If TCP Rst Configured
            if self.on_rst:
                self.logger.debug("Got TCP Rst, While TCP Rst Configured")
                self.multitor.new_identity()
                # Set Response
                flow.response = self.create_response(flow.request)
            else:
                self.logger.error("Got TCP Rst, While TCP Rst Not Configured")
        except Exception as error:
            self.logger.error("Got Unknown Error %s" % error)

        # If String Found On Response Content
        if self.on_string and self.on_string in flow.response.content:
            self.logger.debug("String Found On Response Content")
            self.multitor.new_identity()
            # Set Response
            flow.response = self.create_response(flow.request)

        # If Regex Found On Response Content
        if self.on_regex and re.search(self.on_regex, flow.response.content, re.IGNORECASE):
            self.logger.debug("Regex Found On Response Content")
            self.multitor.new_identity()
            # Set Response
            flow.response = self.create_response(flow.request)

        # If Counter Raised To The Configured Number
        if 0 < next(self.counter) >= self.on_count:
            self.logger.debug("Counter Raised To The Configured Number")
            self.counter = itertools.count(1)
            self.multitor.new_identity()

        # CallBack (For Developers)
        if self.on_callback:
            self.on_callback(self, flow, error)


def run(listen_host="", listen_port=8080, socks=False, auth=None, insecure=False,
        processes=2, cmd='tor',
        on_count=0, on_string=None, on_regex=None, on_rst=False, on_callback=None):
    # Warn If No Change IP Configuration:
    if on_count == 0 and on_string is None and on_regex is None and not on_rst:
        logger.warning("Change IP Configuration Not Set (Acting As Regular Tor Proxy)")

    proxy = MultiTorProxy(
        listen_host=listen_host, listen_port=listen_port, socks=socks, auth=auth, insecure=insecure,
        processes=processes, cmd=cmd,
        on_count=on_count, on_string=on_string, on_regex=on_regex, on_rst=on_rst, on_callback=on_callback
    )

    # Shutdown When Exit (To Be Sure All Cleaned)
    atexit.register(proxy.multitor.shutdown)

    return proxy.run()


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("-v", "--version", action="version", version="%(prog)s {ver}".format(ver=__version__))

    # Proxy Configuration
    parser.add_argument("-lh", "--host",
                        help="Proxy Listen Host.",
                        dest='listen_host',
                        default="127.0.0.1")
    parser.add_argument("-lp", "--port",
                        help="Proxy Listen Port.",
                        dest='listen_port',
                        type=int,
                        default=8080)
    parser.add_argument("-s", "--socks",
                        help="Use As Socks Proxy (Not HTTP Proxy).",
                        action='store_true')
    parser.add_argument("-a", "--auth",
                        help="Set proxy authentication (Format: 'username:pass').",
                        dest='auth')
    parser.add_argument("-i", "--insecure",
                        help="Insecure SSL.",
                        action='store_true')
    parser.add_argument("-d", "--debug",
                        help="Debug Log.",
                        action='store_true')

    # MultiTor Configuration
    parser.add_argument("-p", "--tor-processes",
                        help="Number Of Tor Processes On The Cycle.",
                        dest='processes',
                        type=int,
                        default=2)
    parser.add_argument("-c", "--tor-cmd",
                        help="Tor Cmd (Executable Path + Arguments).",
                        dest='cmd',
                        default="tor")

    # When To Change IP Address
    parser.add_argument("--on-count",
                        help="Change IP Every x Requests (Resources Also Counted).",
                        type=int,
                        default=0)
    parser.add_argument("--on-string",
                        help="Change IP When String Found On The Response Content.",
                        default=None)
    parser.add_argument("--on-regex",
                        help="Change IP When Regex Found On The Response Content.",
                        default=None)
    parser.add_argument("--on-rst",
                        help="Change IP When Connection Closed With TCP RST.",
                        action='store_true')

    sys_args = vars(parser.parse_args(args=args))

    # Configure Logger
    logging.basicConfig(level=logging.DEBUG if sys_args.pop('debug') else logging.INFO,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%d-%m-%y %H:%M:%S')

    # Disable Other Loggers
    logging.getLogger("stem").disabled = True
    logging.getLogger("requests.packages.urllib3.connectionpool").disabled = True

    # Log CMD Args If Debug Mode Enabled
    logger.debug("Running With CMD Args: %s" % json.dumps(sys_args))

    # Run PyMultitor
    run(**sys_args)


if __name__ == '__main__':
    main()
