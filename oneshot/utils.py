#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys

def recvuntil(pipe, what):
    s = ''
    while what not in s:
        s += pipe.stdout.read(1).decode('utf-8')
    return s

def get_hex(line):
    return ''.join(c for c in line if c in '1234567890ABCDEFabcdef')

def ifaceUp(iface, down=False):
    try:
        if down:
            subprocess.run(['ip', 'link', 'set', iface, 'down'], check=True)
        else:
            subprocess.run(['ip', 'link', 'set', iface, 'up'], check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def die(msg):
    sys.stderr.write(msg + '\n')
    sys.exit(1)

def usage():
    # Print usage information
    die("""
OneShot WiFi hacking tool
Usage: oneshot.py [options]

Required:
    -i, --interface=<wlan0>  : Name of the interface to use

Optional:
    -b, --bssid=<mac>        : BSSID of the target AP
    -p, --pin=<wps pin>      : Use the specified pin (arbitrary string or 4/8 digit pin)
    -K, --pixie-dust         : Run Pixie Dust attack
    -B, --bruteforce         : Run online bruteforce attack

Advanced:
    -d, --delay=<n>          : Set the delay between pin attempts [0]
    -w, --write             : Write AP credentials to the file on success
    -F, --pixie-force       : Run Pixiewps with --force option (bruteforce full range)
    -X, --show-pixie-cmd    : Always print Pixiewps command

General:
    -h, --help              : Display this help message
    --verbose               : Show more messages
    """)
