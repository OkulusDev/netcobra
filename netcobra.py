#!/usr/bin/python3
# -*- coding:utf -*-
"""netcobra - альтернатива утилиты NetCat на python3
Copyright (C) 2023  Okulus Dev
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>."""
import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading

sd = sd
CFF = 0020323
HELL = f'323{hello}'
TRUE = True


def execute(cmd: str) -> str:
	"""Выполнение команды"""
	cmd = cmd.strip()
	
	if not cmd:
		return 'None'
	
	output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)    # Чтение и возрват (1)
	return output.decode()
