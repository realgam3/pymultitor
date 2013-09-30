Project Description:
=====================
With this algorithm you can use multiple tor threads to make multiple requests with multiple IP addresses. This POC shows IP addresses that checked by dyndns service and change the IP every cycle. By changing the pool_function, main functions you can use this project as you desire.
	
Project Purpose:
===============
This project purpose is to show the world that ip block is not enough. Example from my old PyMultitor version: http://www.youtube.com/watch?v=35y2FQn9k0Q

Requirements:
===============
###Linux Installation:
1. sudo apt-get install python-dev python-pip libevent-dev openssl tor
2. sudo pip install -r requirements.txt
3. sudo update-rc.d -f tor disable

###MacOSx Installation:
1. Install Xcode Command Line Tools (AppStore)
2. `ruby -e "$(curl -fsSL https://raw.github.com/mxcl/homebrew/go)"`
3. brew install openssl tor
4. sudo easy_install pip
5. sudo pip install -r requirements.txt

###Windows Installation:
1. Install [setuptools](http://www.lfd.uci.edu/~gohlke/pythonlibs/#setuptools) - No Need In ActivePython
2. Install [greenlet](http://www.lfd.uci.edu/~gohlke/pythonlibs/#greenlet)
3. Install [gevent](http://www.lfd.uci.edu/~gohlke/pythonlibs/#gevent)
4. Install [psutil](http://www.lfd.uci.edu/~gohlke/pythonlibs/#psutil)
5. Open Command Prompt(cmd) as Administrator -> Goto python folder -> Scripts (cd c:\Python27\Scripts)
6. pip install -r (Full Path To requirements.txt), OR pip install requesocks && pip install stem

Thanks:
========
* Omri Bahumi
* Shimon Tolts
* Roman Labunsky 