import os
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
from time import sleep
from shutil import rmtree
from mitmproxy import ctx
from tempfile import mkdtemp
from flask import Flask, jsonify
from mitmproxy.http import Response
from collections.abc import Sequence
from mitmproxy.addons import asgiapp
from mitmproxy.tools.main import mitmdump
from multiprocessing.pool import ThreadPool
from stem.control import Controller, Signal
from requests.exceptions import ConnectionError
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from stem.process import launch_tor_with_config, DEFAULT_INIT_TIMEOUT

__version__ = "4.0.0"
__author__ = 'Tomer Zait (realgam3)'

app = Flask("pymultitor")
token = os.getenv("PYMULTITOR_TOKEN", os.urandom(32).hex())


def is_windows():
    return platform.system().lower() == "windows"


def monkey_patch():
    _log_mitmproxy = logging.getLogger("mitmproxy")

    # Patch mitmproxy.addons.termlog.log
    from mitmproxy.addons import termlog

    def _termlog_log(self, e):
        getattr(_log_mitmproxy, e.level)(e.msg)

    setattr(termlog.TermLog, "log", _termlog_log)

    # Patch mitmproxy.addon.dumper.echo & mitmproxy.addon.dumper.echo_error
    from mitmproxy.addons import dumper

    def _dumper_echo(self, text, ident=None, **style):
        if ident:
            text = dumper.indent(ident, text)
        _log_mitmproxy.info(text)

    setattr(dumper.Dumper, "echo", _dumper_echo)

    def _dumper_echo_error(self, text, **style):
        _log_mitmproxy.error(text)

    setattr(dumper.Dumper, "echo_error", _dumper_echo_error)


class Tor(object):
    def __init__(self, cmd="tor", config=None, timeout=DEFAULT_INIT_TIMEOUT, tries=5):
        self.logger = logging.getLogger(__name__)
        self.tor_cmd = cmd
        self.tor_config = config or {}
        self.tor_timeout = timeout
        self.tries = tries
        self.socks_port = self.free_port()
        self.control_port = self.free_port()
        self.data_directory = mkdtemp()
        self.id = self.socks_port
        self.process = None
        self.controller = None
        self._is_running = False
        self.__is_shutdown = False

    def __del__(self):
        self.shutdown()

    def __enter__(self):
        return self.run()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

    def run(self):
        self.logger.debug(f"[{self.id:05d}] Executing Tor Process")
        for i in range(self.tries):
            try:
                self.process = launch_tor_with_config(
                    config={
                        "ControlPort": str(self.control_port),
                        "SOCKSPort": str(self.socks_port),
                        "DataDirectory": self.data_directory,
                        "AllowSingleHopCircuits": "1",
                        "ExcludeSingleHopRelays": "0",
                        **self.tor_config
                    },
                    tor_cmd=self.tor_cmd,
                    timeout=self.tor_timeout if self.tor_timeout != 0 else None,
                    init_msg_handler=self.print_bootstrapped_line
                )
                break
            except Exception as error:
                self.logger.debug(
                    f"[{self.id:05d}] Tor Process Execution Failed With The Error ({i + 1}/{self.tries}): {repr(error)}"
                )

        self.logger.debug(f"[{self.id:05d}] Creating Tor Controller")
        self.controller = Controller.from_port(port=self.control_port)
        self.controller.authenticate()

        return self

    def shutdown(self):
        if self.__is_shutdown:
            return

        self._is_running = False
        self.__is_shutdown = True
        self.logger.debug(f"[{self.id:05d}] Destroying Tor")
        self.controller.close()
        self.process.terminate()
        self.process.wait()

        # If Not Closed Properly
        if path.exists(self.data_directory):
            rmtree(self.data_directory)

    def newnym_available(self):
        return self.controller.is_newnym_available()

    def newnym_wait(self):
        return self.controller.get_newnym_wait()

    def newnym(self):
        if not self.newnym_available():
            self.logger.debug(f"[{self.id:05d}] Could Not Change Tor Identity (Wait {round(self.newnym_wait())}s)")
            return False

        self.logger.info(f"[{self.id:05d}] Changing Tor Identity")
        self.controller.signal(Signal.NEWNYM)
        return True

    def print_bootstrapped_line(self, line):
        if "Bootstrapped" in line:
            self.logger.debug(f"[{self.id:05d}] Tor Bootstrapped Line: {line}")

            if "100%" in line:
                self._is_running = True
                self.logger.debug(f"[{self.id:05d}] Tor Process Executed Successfully")

    @staticmethod
    def free_port():
        """
        Determines a free port using sockets.
        Taken from selenium python.
        """
        free_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        free_socket.bind(("0.0.0.0", 0))
        free_socket.listen(5)
        port = free_socket.getsockname()[1]
        free_socket.close()
        return port


class MultiTor(object):
    def __init__(self, size=2, cmd="tor", config=None, timeout=DEFAULT_INIT_TIMEOUT, tries=5):
        self.logger = logging.getLogger(__name__)
        self.cmd = cmd
        self.timeout = timeout
        self.tries = tries
        self.size = size
        self.list = []
        self.cycle = None
        self.current = None
        self.config = self.parse_config(config)

    def parse_config(self, config=None):
        config = config or {}

        cfg = {}
        try:
            if isinstance(config, dict):
                cfg = config
            elif path.isfile(config):
                with open(config, encoding="utf-8") as cfg_file:
                    json.load(cfg_file)
            else:
                cfg = json.loads(config)
        except (TypeError, json.JSONDecodeError):
            self.logger.error(f"Could Not Parse Extended JSON Configuration: {repr(config)}")
            return {}
        except Exception as error:
            self.logger.error(f"Tor Configuration Parsing Error: {repr(error)}")
            return {}

        # Remove Port / Data Configurations
        cfg.pop("ControlPort", None)
        cfg.pop("SOCKSPort", None)
        cfg.pop("DataDirectory", None)

        self.logger.debug(f"Tor Extended Configuration: {json.dumps(cfg)}")
        return cfg

    def run(self):
        self.logger.info(f"Executing {self.size} Tor Processes")

        timeout = self.timeout
        if is_windows():
            # Feature Won't Work In Windows
            timeout = DEFAULT_INIT_TIMEOUT

        pool = ThreadPool(processes=self.size)
        self.list = pool.map(
            func=lambda _: Tor(
                cmd=self.cmd,
                config=self.config,
                timeout=timeout,
                tries=self.tries,
            ).run(),
            iterable=range(self.size)
        )

        self.logger.info("All Tor Processes Executed Successfully")
        self.cycle = itertools.cycle(self.list)
        self.current = next(self.cycle)

    @property
    def proxy(self):
        proxy_url = f"socks5://127.0.0.1:{self.current.socks_port:d}"
        return {"http": proxy_url, "https": proxy_url}

    def new_identity(self):
        identity_changed = False
        while not identity_changed:
            identity_changed = self.current.newnym()
            self.current = next(self.cycle)
            if not identity_changed:
                sleep(0.1)

        return self.proxy

    def shutdown(self):
        for tor in self.list:
            tor.shutdown()


class PyMultiTor(object):
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.insecure = False
        self.request_timeout = 0

        # Change IP Policy (Configuration)
        self.counter = itertools.count()
        self.on_count = 0
        self.on_string = ""
        self.on_regex = ""
        self.on_rst = False
        self.on_status_code = []
        self.on_timeout = False

        self.multitor = None

    @staticmethod
    def load(loader):
        # MultiTor Configuration
        loader.add_option(
            name="tor_processes",
            typespec=int,
            default=2,
            help="number of tor processes in the cycle",
        )
        loader.add_option(
            name="tor_cmd",
            typespec=str,
            default="tor",
            help="tor cmd (executable path + arguments)",
        )
        loader.add_option(
            name="tor_config",
            typespec=str,
            default="{}",
            help="tor extended json configuration",
        )
        loader.add_option(
            name="tor_timeout",
            typespec=int,
            default=DEFAULT_INIT_TIMEOUT,
            help="timeout in seconds for starting a tor instance; 0 disables timeout",
        )
        loader.add_option(
            name="tor_tries",
            typespec=int,
            default=5,
            help="number tries to execute tor instance before it fails",
        )
        loader.add_option(
            name="request_timeout",
            typespec=int,
            default=0,
            help="timeout in seconds for http requests; 0 disables timeout",
        )

        # When To Change IP Address
        loader.add_option(
            name="on_count",
            typespec=int,
            default=0,
            help="change ip every x requests (resources also counted)",
        )
        loader.add_option(
            name="on_string",
            typespec=str,
            default="",
            help="change ip when string found in the response content",
        )
        loader.add_option(
            name="on_regex",
            typespec=str,
            default="",
            help="change ip when regex found in The response content",
        )
        loader.add_option(
            name="on_rst",
            typespec=bool,
            default=False,
            help="change ip when connection closed with tcp rst",
        )
        loader.add_option(
            name="on_status_code",
            typespec=Sequence[str],
            default=[],
            help="change ip when one of the specified status codes is returned",
        )
        loader.add_option(
            name="on_timeout",
            typespec=bool,
            default=False,
            help="change ip when request times out",
        )

    def configure(self, updates):
        # Configure Logger
        logging.basicConfig(level=logging.DEBUG if ctx.options.termlog_verbosity.lower() == "debug" else logging.INFO,
                            format="%(asctime)s %(levelname)-8s %(message)s",
                            datefmt="%d-%m-%y %H:%M:%S")

        # Disable Loggers
        monkey_patch()
        for logger_name in ["stem", "urllib3.connectionpool", "mitmproxy"]:
            logging.getLogger(logger_name).disabled = True

        # Log CMD Args If Debug Mode Enabled
        cmd_args = json.dumps({update: getattr(ctx.options, update) for update in updates})
        self.logger.debug(f"Running With CMD Args: {cmd_args}")

        self.on_count = ctx.options.on_count
        self.on_string = ctx.options.on_string
        self.on_regex = ctx.options.on_regex
        self.on_rst = ctx.options.on_rst
        self.on_status_code = [int(x) for x in ctx.options.on_status_code]
        self.on_timeout = ctx.options.on_timeout

        self.insecure = ctx.options.ssl_insecure
        self.request_timeout = ctx.options.request_timeout

        self.logger.info(f"PyMultiTor Token: {token}")

        self.multitor = MultiTor(
            size=ctx.options.tor_processes,
            cmd=ctx.options.tor_cmd,
            config=ctx.options.tor_config,
            timeout=ctx.options.tor_timeout,
            tries=ctx.options.tor_tries,
        )
        try:
            self.multitor.run()
        except KeyboardInterrupt:
            self.multitor.shutdown()

        atexit.register(self.multitor.shutdown)

        # Warn If No Change IP Configuration:
        if not any([self.on_count, self.on_string, self.on_regex, self.on_rst, self.on_status_code, self.on_timeout]):
            self.logger.warning("Change IP Configuration Not Set (Acting As Regular Tor Proxy)")

    def create_response(self, request):
        response = requests.request(
            method=request.method,
            url=request.url,
            data=request.content,
            headers=request.headers,
            allow_redirects=False,
            verify=not self.insecure,
            proxies=self.multitor.proxy,
            stream=False,
            timeout=self.request_timeout if self.request_timeout != 0 else None,
        )

        # Content-Length and Transfer-Encoding set. This is expressly forbidden by RFC 7230 sec 3.3.2.
        if response.headers.get("Transfer-Encoding") == "chunked":
            response.headers.pop("Transfer-Encoding")

        return Response.make(
            status_code=response.status_code,
            content=response.content,
            headers=dict(response.headers),
        )

    def request(self, flow):
        auth = flow.request.headers.get("Proxy-Authorization", "").split(" ", 2)
        if flow.request.host in ["pymultitor"] and len(auth) == 2 and auth[1] == token:
            return

        error_message = None
        try:
            flow.response = self.create_response(flow.request)
        except ConnectionError:
            # If TCP Rst Configured
            if self.on_rst:
                self.logger.debug("Got TCP Rst, While TCP Rst Configured")
                self.multitor.new_identity()
                # Set Response
                try:
                    flow.response = self.create_response(flow.request)
                except Exception as error:
                    error_message = f"After TCP Rst Triggered, Got Response Error: {repr(error)}"
            else:
                error_message = "Got TCP Rst, While TCP Rst Not Configured"
        except requests.exceptions.Timeout:
            # If Timeout Configured
            if self.on_timeout:
                self.logger.debug("Request Timeout, While Timeout Configured")
                self.multitor.new_identity()
                # Set Response
                try:
                    flow.response = self.create_response(flow.request)
                except Exception as error:
                    error_message = f"After Timeout Triggered, Got Response Error: {repr(error)}"
            else:
                error_message = "Request Timeout, While Timeout Not Configured"
        except Exception as error:
            error_message = f"Got Response Error: {repr(error)}"

        # When There Is No Response
        if error_message:
            self.logger.error(error_message)
            # Set Error Response
            flow.response = Response.make(
                status_code=500,
                content=error_message,
                headers={
                    "Server": f"pymultitor/{__version__}"
                }
            )
            return

        # If String Found In Response Content
        if self.on_string and self.on_string in flow.response.text:
            self.logger.debug("String Found In Response Content")
            self.multitor.new_identity()
            # Set Response
            flow.response = self.create_response(flow.request)

        # If Regex Found In Response Content
        if self.on_regex and re.search(self.on_regex, flow.response.text, re.IGNORECASE):
            self.logger.debug("Regex Found In Response Content")
            self.multitor.new_identity()
            # Set Response
            flow.response = self.create_response(flow.request)

        # If Counter Raised To The Configured Number
        if self.on_count and not next(self.counter) % self.on_count:
            self.logger.debug("Counter Raised To The Configured Number")
            self.multitor.new_identity()

        # If A Specific Status Code Returned
        if flow.response.status_code in self.on_status_code:
            self.logger.debug("Specific Status Code Returned")
            self.multitor.new_identity()
            # Set Response
            flow.response = self.create_response(flow.request)


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("-v", "--version", action="version", version="%(prog)s {ver}".format(ver=__version__))

    # Proxy Configuration
    parser.add_argument("-lh", "--host",
                        help="proxy listen host.",
                        dest="listen_host",
                        default="127.0.0.1")
    parser.add_argument("-lp", "--port",
                        help="proxy listen port",
                        dest="listen_port",
                        type=int,
                        default=8080)
    parser.add_argument("-s", "--socks",
                        help="use as socks proxy (not http proxy)",
                        action="store_true")
    parser.add_argument("-a", "--auth",
                        help="set proxy authentication (format: 'username:pass')",
                        dest="auth",
                        default="")
    parser.add_argument("-i", "--insecure",
                        help="insecure ssl",
                        action="store_true")
    parser.add_argument("-d", "--debug",
                        help="Debug Log.",
                        action="store_true")

    # MultiTor Configuration
    parser.add_argument("-p", "--tor-processes",
                        help="number of tor processes in the cycle",
                        dest="processes",
                        type=int,
                        default=2)
    parser.add_argument("-c", "--tor-cmd",
                        help="tor cmd (executable path + arguments)",
                        dest="cmd",
                        default="tor")
    parser.add_argument("-e", "--tor-config",
                        help="tor extended json configuration",
                        dest="config",
                        default="{}")
    parser.add_argument("-t", "--tor-timeout",
                        help="timeout in seconds for starting a tor instance; 0 disables timeout",
                        dest="timeout",
                        type=int,
                        default=DEFAULT_INIT_TIMEOUT)
    parser.add_argument("-r", "--tor-tries",
                        help="number tries to start a tor instance before it fails",
                        dest="tries",
                        type=int,
                        default=5)
    parser.add_argument("--request-timeout",
                        help="timeout in seconds for http requests; 0 disables timeout",
                        dest="request_timeout",
                        type=int,
                        default=0)

    # When To Change IP Address
    parser.add_argument("--on-count",
                        help="change ip every x requests (resources also counted)",
                        type=int,
                        default=0)
    parser.add_argument("--on-string",
                        help="change ip when string found in the response content",
                        default="")
    parser.add_argument("--on-regex",
                        help="change ip when regex found in The response content",
                        default="")
    parser.add_argument("--on-rst",
                        help="change ip when connection closed with tcp rst",
                        action="store_true")
    parser.add_argument("--on-status-code",
                        help="change ip when one of the specified status codes is returned",
                        type=int,
                        nargs='*',
                        default=[])
    parser.add_argument("--on-timeout",
                        help="change ip when request times out",
                        action="store_true")

    sys_args = vars(parser.parse_args(args=args))
    mitmdump_args = [
        "--scripts", __file__,
        "--mode", "socks5" if sys_args['socks'] else "regular",
        "--listen-host", sys_args['listen_host'],
        "--listen-port", str(sys_args['listen_port']),
        "--set", f"tor_cmd={sys_args['cmd']}",
        "--set", f"tor_config={sys_args['config']}",
        "--set", f"tor_timeout={sys_args['timeout']}",
        "--set", f"tor_tries={sys_args['tries']}",
        "--set", f"tor_processes={sys_args['processes']}",
        "--set", f"request_timeout={sys_args['request_timeout']}",
        "--set", f"on_string={sys_args['on_string']}",
        "--set", f"on_regex={sys_args['on_regex']}",
        "--set", f"on_count={sys_args['on_count']}",
    ]

    for status_code in sys_args["on_status_code"]:
        mitmdump_args.extend([
            "--set", f"on_status_code={status_code}",
        ])

    if sys_args["auth"]:
        mitmdump_args.extend([
            "--proxyauth", sys_args["auth"],
        ])

    if sys_args["on_rst"]:
        mitmdump_args.extend([
            "--set", "on_rst",
        ])

    if sys_args["on_timeout"]:
        mitmdump_args.extend([
            "--set", "on_timeout",
        ])

    if sys_args["debug"]:
        mitmdump_args.extend([
            "--verbose",
        ])

    if sys_args["insecure"]:
        mitmdump_args.extend([
            "--ssl-insecure",
        ])
    return mitmdump(args=mitmdump_args)


@app.route("/status")
def hello_world() -> Response:
    is_running = False
    if pymultitor.multitor:
        is_running = all([
            tor._is_running
            for tor in pymultitor.multitor.list
        ])

    return jsonify({
        "status": "running" if is_running else "stopped",
    })


pymultitor = PyMultiTor()
addons = [
    asgiapp.WSGIApp(app, "pymultitor", 80),
    pymultitor,
]

if __name__ == "__main__":
    main()
