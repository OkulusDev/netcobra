PI=python3
PIP=pip3
SRC=netcobra.py
BIN=netcobra
REQ_FILE=requirements.txt
ICO=res/netcobra.ico
FLAGS=--clang --output-filename=$(BIN) --remove-output --lto=yes --product-name=NetCobra --file-description="Program for networking" --enable-console

install:
	$(PIP) install -r $(REQ_FILE)
	openssl req -new -newkey rsa:3072 -days 365 -nodes -x509 -keyout server.key -out server.crt
	openssl req -new -newkey rsa:3072 -days 365 -nodes -x509 -keyout client.key -out client.crt

build:
	nuitka3 $(SRC) $(FLAGS) --linux-icon=$(ICO)

build_win:
	nuitka3 $(SRC) $(FLAGS) --windows-icon-from-ico=$(ICO)

build_mac:
	nuitka3 $(SRC) $(FLAGS) --macos-app-icon=$(ICO)
