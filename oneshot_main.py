#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import getopt

from oneshot.utils import die, usage, ifaceUp
from oneshot.companion import Companion
from oneshot.wifi import WiFiScanner

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:b:p:d:KBFXwh",
            ["interface=", "bssid=", "pin=", "delay=", "pixie-dust",
             "bruteforce", "pixie-force", "show-pixie-cmd", "write",
             "help", "verbose"])
    except getopt.GetoptError as err:
        die(str(err))

    interface = None
    bssid = None
    pin = None
    delay = None
    pixiemode = False
    bruteforce = False
    pixieforce = False
    showpixiecmd = False
    write = False
    verbose = False

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
        elif opt in ('-i', '--interface'):
            interface = arg
        elif opt in ('-b', '--bssid'):
            bssid = arg
        elif opt in ('-p', '--pin'):
            pin = arg
        elif opt in ('-d', '--delay'):
            try:
                delay = int(arg)
            except ValueError:
                die('Delay must be an integer')
        elif opt in ('-K', '--pixie-dust'):
            pixiemode = True
        elif opt in ('-B', '--bruteforce'):
            bruteforce = True
        elif opt in ('-F', '--pixie-force'):
            pixieforce = True
        elif opt in ('-X', '--show-pixie-cmd'):
            showpixiecmd = True
        elif opt in ('-w', '--write'):
            write = True
        elif opt == '--verbose':
            verbose = True

    if interface is None:
        die('Interface must be specified')

    if not ifaceUp(interface):
        die('Unable to up interface "{}"'.format(interface))

    try:
        companion = Companion(interface, save_result=write, print_debug=verbose)
        if not bruteforce and pin is None and not pixiemode:
            scanner = WiFiScanner(interface)
            if bssid is None:
                bssid = scanner.prompt_network()
            pin = companion.__prompt_wpspin(bssid)

        if bruteforce:
            companion.smart_bruteforce(bssid, pin, delay)
        else:
            companion.single_connection(bssid=bssid, pin=pin,
                pixiemode=pixiemode,
                showpixiecmd=showpixiecmd,
                pixieforce=pixieforce)
    except KeyboardInterrupt:
        die('Interrupted by user')

if __name__ == '__main__':
    main()
