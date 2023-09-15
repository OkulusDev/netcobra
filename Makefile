PI=python3
PIP=pip3
SRC=netcobra.py
BIN=netcobra
REQ_FILE=requirements.txt
ICO=res/netcobra.ico

install:
	$(PIP) install -r $(REQ_FILE)
	openssl req -new -newkey rsa:3072 -days 365 -nodes -x509 -keyout server.key -out server.crt
	openssl req -new -newkey rsa:3072 -days 365 -nodes -x509 -keyout client.key -out client.crt

build:
	nuitka3 $(SRC) --output-filename=$(BIN) --remove-output --linux-icon=$(ICO) --macos-app-icon=$(ICO) --windows-icon-from-ico=$(ICO)
