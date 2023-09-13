PI=python3
PIP=pip3
SRC=netcobra.py
BIN=netcobra
REQ_FILE=requirements.txt

install:
	$(PIP) install -r $(REQ_FILE)
