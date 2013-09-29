#!/usr/bin/env python
########################################################
#           Python MultiTor
#           Author: RealGame (Tomer Zait)
#           Site:   http://RealGame.co.il
########################################################

#Monkey Patch All - Change Everything To Gevent
from gevent.monkey import patch_all
patch_all()

from TorConfig import *
from gevent import Timeout
from re import findall
from os import makedirs
from time import time as now
from requesocks import request
from stem.process import launch_tor_with_config
from stem.control import Controller
from stem import Signal, util
from zipfile import ZipFile
from psutil import process_iter
from subprocess import check_output
import logging
import atexit


#TorConnection - Contains Controller And Subprocess
class TorConnection(object):
    def __init__(self, socksPort, ctrlPort):
        #Variables
        self.__isFree = False
        self.__socksPort = socksPort
        self.__ctrlPort = ctrlPort
        self.__torConfig = None
        self.__torProcess = None
        self.__torCtrl = None
        self.__proxies = None
        self.__lastTimeIpChanged = 0

        #Call Creator
        self.__start()

    def __torPrint(self, line):
        if "Bootstrapped" in line:
            logger.info("%s\t->\t%s" % (self.getId(), line))

    def __open(self):
        #Open Tor Process
        opened = False
        while not opened:
            with Timeout(PROCESS_TIMEOUT, False):
                self.__torProcess = launch_tor_with_config(config=self.__torConfig,
                                                           tor_cmd=TOR_CMD,
                                                           init_msg_handler=self.__torPrint)
                self.__torProcess.stdout.close()
                opened = True
            if not opened:
                self.__torProcess.terminate()
        
        #Open Tor Control
        self.__torCtrl = Controller.from_port(address=HOST, port=self.__ctrlPort)
        self.__torCtrl.authenticate(PASS_PHRASE)
    
    def __start(self):
        #Data Paths
        dataPath = path.join(TOR_ROOT_DATA_PATH, "data_%d" % self.__socksPort)
        if not path.exists(dataPath):
            makedirs(dataPath)
        
        #Create Configuration Dictionary
        self.__torConfig = {"ControlPort": str(self.__ctrlPort),
                            "HashedControlPassword": passPhraseHash,
                            "ExcludeNodes": "{CN},{HK},{MO}",
                            "SOCKSPort": str(self.__socksPort),
                            "DataDirectory": dataPath}

        #Open Tor Process
        self.__open()
        
        #Create Proxy String
        self.__proxies = {"http": "socks5://%s:%d" % (HOST, self.__socksPort),
                          "https": "socks5://%s:%d" % (HOST, self.__socksPort)}

        #The Tor Connection Is Now Ready To Use
        self.__isFree = True

        #Up And Running Message
        logger.info("%s\t->\tUp & Running!" % self.getId())

    def changeState(self):
        self.__isFree = not self.__isFree

    def isFree(self):
        return self.__isFree

    def kill(self):
        with Timeout(TOR_TIMEOUT, False):
            self.__torCtrl.close()
        self.__torProcess.terminate()

    def reset(self):
        #Kill All
        self.kill()

        #Start All
        self.__open()

        #Inform
        logger.info("%s\t->\tUp & Running After Reset!" % self.getId())
        
    def changeIp(self, i, msg):
        #Tor Need 10 Seconds(TOR_TIMEOUT) Difference Between Id Changes
        if (now() - self.__lastTimeIpChanged) >= TOR_TIMEOUT:
            logger.info("%s\t->\t%d) ChangeIP (%s)" % (self.getId(), i, msg))

            #Check If TimedOut
            timedOut = True
            with Timeout(TOR_TIMEOUT, False):
                self.__torCtrl.signal(Signal.NEWNYM)
                timedOut = False
            if timedOut:
                self.reset()

            self.__lastTimeIpChanged = now()
            return True
        return False

    def getId(self):
        return "Tor[%d]" % self.__socksPort

    def getProxies(self):
        return self.__proxies


class TorConnectionCollector(object):
    """
    TorConnectionCollector - Sends Free TorConnection To The Thread Function
    """
    def __init__(self):
        self.__torCons = []
        for i in xrange(MAX_NUM_OF_THREADS):
            self.__torCons.append(TorConnection(SOCKS_START_PORT + i, CONTROL_START_PORT + i))

    def getFreeConnection(self):
        while True:
            for conn in self.__torCons:
                if conn.isFree():
                    conn.changeState()
                    return conn

    def killConnections(self):
        print "Killing tor!"
        logger.info("Killing all tor clients")
        for conn in self.__torCons:
            conn.kill()


def pool_function(torRange):
    #Important variables
    torConn = torConnColl.getFreeConnection()
    proxies = torConn.getProxies()
    torId = torConn.getId()
    size = len(torRange)

    logger.info("%s\t->\tStart (%d - %d)" % (torId, torRange[0], torRange[-1]))
    i = 0

    #Using a while loop - cant move backwards
    while i < size:
        try:
            #Send Request
            req = request(method="GET",
                          url="http://checkip.dyndns.org/",
                          timeout=REQUEST_TIMEOUT,
                          headers=HEADERS,
                          proxies=proxies)
            res = req.text
            if res == "":
                continue
        except Exception as ex:
            #Change IP
            ipChanged = False
            while not ipChanged:
                ipChanged = torConn.changeIp(torRange[i], ex)
            continue

        #Print Result
        logger.debug("%s\t->\t(req %d) %s" % (torId, torRange[i], "".join(findall(r"[0-9]+(?:\.[0-9]+){3}", res))))
        i += 1
        
    #Change IP
    ipChanged = False
    while not ipChanged:
        ipChanged = torConn.changeIp(i, "Finished.")

    #Free The TorConnection
    torConn.changeState()


def start_logging():
    global logger
    logger = logging.getLogger('screenLogger')
    logger.setLevel(logging.DEBUG)

    #create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter('%(asctime)s:%(levelname)s - %(message)s')

    # add formatter
    ch.setFormatter(formatter)


    # add entities to logger
    logger.addHandler(ch)


def main():
    try:
        #Start logger
        start_logging()

        #initiate on exit function
        atexit.register(exit_function)

        #Startup print
        logger.info("Starting PyMultiTor with %s Threads..." % MAX_NUM_OF_THREADS)

        #Kill All Tor Processes
        for process in process_iter():
            if path.basename(TOR_CMD) == process.name:
                process.terminate()

        #Extract Tor Windows Files If Needed
        if isWindows() and not path.exists(TOR_ROOT_DATA_PATH):
            makedirs(TOR_ROOT_DATA_PATH)
            ZipFile(path.join(getcwd(), "torWin.data")).extractall(TOR_ROOT_DATA_PATH)

        #Create TorConnectionCollector And Tor PassPhrase Hash
        global torConnColl, passPhraseHash
        passPhraseHash = check_output([TOR_CMD, "--hash-password", PASS_PHRASE]).strip().split("\n")[-1]
        torConnColl = TorConnectionCollector()

        #Create The Threads Pool
        for i in xrange(START, END, INC):
            POOL.spawn(pool_function, range(i, i + INC))

        #Block Until Pool Done
        POOL.join()

        #Kill All TorConnections
        logger.info("Kill Tor Connections")
        torConnColl.killConnections()

        #Finish
        logger.info("Finished Scanning")
    except:
        pass


def exit_function():
    print "\nPerforming clean exit... shutting down tor clients..."
    print "Thank you for using PyMultiTor - https://github.com/realgam3/pymultitor"

if __name__ == "__main__":
    main()

