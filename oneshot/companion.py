#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import os
import tempfile
import socket
import pathlib
import time
from datetime import datetime
import collections
import statistics
import csv
from pathlib import Path

from .wps import WPSpin
from .pixie import PixiewpsData
from .connection import ConnectionStatus, BruteforceStatus
from .utils import recvuntil, get_hex

class Companion:
    """Main application part"""
    def __init__(self, interface, save_result=False, print_debug=False):
        self.interface = interface
        self.save_result = save_result
        self.print_debug = print_debug

        self.tempdir = tempfile.mkdtemp()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp:
            temp.write('ctrl_interface={}\nctrl_interface_group=root\nupdate_config=1\n'.format(self.tempdir))
            self.tempconf = temp.name
        self.wpas_ctrl_path = f"{self.tempdir}/{interface}"
        self.__init_wpa_supplicant()

        self.res_socket_file = f"{tempfile._get_default_tempdir()}/{next(tempfile._get_candidate_names())}"
        self.retsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.retsock.bind(self.res_socket_file)

        self.pixie_creds = PixiewpsData()
        self.connection_status = ConnectionStatus()

        user_home = str(pathlib.Path.home())
        self.sessions_dir = f'{user_home}/.OneShot/sessions/'
        self.pixiewps_dir = f'{user_home}/.OneShot/pixiewps/'
        self.reports_dir = os.path.dirname(os.path.realpath(__file__)) + '/reports/'
        if not os.path.exists(self.sessions_dir):
            os.makedirs(self.sessions_dir)
        if not os.path.exists(self.pixiewps_dir):
            os.makedirs(self.pixiewps_dir)

        self.generator = WPSpin()

    def __init_wpa_supplicant(self):
        pass  # Implementation needed

    def sendOnly(self, command):
        """Sends command to wpa_supplicant"""
        pass  # Implementation needed

    def sendAndReceive(self, command):
        """Sends command to wpa_supplicant and returns the reply"""
        pass  # Implementation needed

    def _explain_wpas_not_ok_status(self, command: str, respond: str):
        pass  # Implementation needed

    def __handle_wpas(self, pixiemode=False, pbc_mode=False, verbose=None):
        pass  # Implementation needed

    def __runPixiewps(self, showcmd=False, full_range=False):
        pass  # Implementation needed

    def __credentialPrint(self, wps_pin=None, wpa_psk=None, essid=None):
        pass  # Implementation needed

    def __saveResult(self, bssid, essid, wps_pin, wpa_psk):
        pass  # Implementation needed

    def __savePin(self, bssid, pin):
        pass  # Implementation needed

    def __prompt_wpspin(self, bssid):
        pass  # Implementation needed

    def __wps_connection(self, bssid=None, pin=None, pixiemode=False, pbc_mode=False, verbose=None):
        pass  # Implementation needed

    def single_connection(self, bssid=None, pin=None, pixiemode=False, pbc_mode=False, showpixiecmd=False,
                         pixieforce=False, store_pin_on_fail=False):
        pass  # Implementation needed

    def __first_half_bruteforce(self, bssid, f_half, delay=None):
        """
        @f_half — 4-character string
        """
        pass  # Implementation needed

    def __second_half_bruteforce(self, bssid, f_half, s_half, delay=None):
        """
        @f_half — 4-character string
        @s_half — 3-character string
        """
        pass  # Implementation needed

    def smart_bruteforce(self, bssid, start_pin=None, delay=None):
        pass  # Implementation needed

    def cleanup(self):
        """Cleanup resources"""
        try:
            shutil.rmtree(self.tempdir)
            os.remove(self.res_socket_file)
        except:
            pass

    def __del__(self):
        self.cleanup()
