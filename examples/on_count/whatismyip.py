import socket
import requests
from os import path
from time import sleep
from multiprocessing import Process
from importlib.machinery import SourceFileLoader

__folder__ = path.dirname(__file__)


def check_pymultitor(address='127.0.0.1', port=8080):
    s = socket.socket()
    try:
        s.connect((address, port))
        return True
    except socket.error:
        return False


def execute_pymultitor():
    pymultitor_path = path.abspath(path.join(__folder__, '..', '..', 'pymultitor.py'))
    pymultitor_module = SourceFileLoader('pymultitor', pymultitor_path).load_module("pymultitor")
    process = Process(target=pymultitor_module.main, kwargs={
        'args': ['-d', '-p', '5', '--on-count', '2']
    })
    process.start()

    while not check_pymultitor():
        sleep(1)

    return process


if __name__ == '__main__':
    process = execute_pymultitor()

    for i in range(20):
        res = requests.get('http://httpbin.org/ip', proxies={'http': '127.0.0.1:8080'}).json()
        print("%d) %s" % (i + 1, res['origin']))

    process.terminate()
    process.join()
