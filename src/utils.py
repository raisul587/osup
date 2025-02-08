#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import subprocess
from pathlib import Path

def ifaceUp(iface, down=False):
    """
    Bring network interface up or down
    @iface: Interface name
    @down: If True, bring interface down instead of up
    Returns True on success, False otherwise
    """
    action = 'down' if down else 'up'
    cmd = f'ip link set {iface} {action}'
    res = subprocess.run(cmd, shell=True, stdout=sys.stdout, stderr=sys.stdout)
    return res.returncode == 0

def die(msg):
    """Print error message and exit with error code 1"""
    sys.stderr.write(msg + '\n')
    sys.exit(1)

def recvuntil(pipe, what):
    """Read from pipe until specific string is found"""
    s = ''
    while True:
        inp = pipe.stdout.read(1)
        if inp == '':
            return s
        s += inp
        if what in s:
            return s

def get_hex(line):
    """Extract hex value from line containing format 'something:hex:value'"""
    a = line.split(':', 3)
    return a[2].replace(' ', '').upper()

def colored(text, color=None):
    """Returns colored text for terminal output"""
    if color:
        if color == 'green':
            text = '\033[92m{}\033[00m'.format(text)
        elif color == 'red':
            text = '\033[91m{}\033[00m'.format(text)
        elif color == 'yellow':
            text = '\033[93m{}\033[00m'.format(text)
        else:
            return text
    return text

def truncateStr(s, length, postfix='…'):
    """
    Truncate string with the specified length
    @s — input string
    @length — length of output string
    """
    if len(s) > length:
        k = length - len(postfix)
        s = s[:k] + postfix
    return s 