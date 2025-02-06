#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import csv

class WiFiScanner:
    """WiFi scanning and network handling functionality"""
    def __init__(self, interface, vuln_list=None):
        self.interface = interface
        self.vuln_list = vuln_list

        reports_fname = os.path.dirname(os.path.realpath(__file__)) + '/reports/stored.csv'
        try:
            with open(reports_fname, 'r', newline='', encoding='utf-8', errors='replace') as file:
                csvReader = csv.reader(file, delimiter=';', quoting=csv.QUOTE_ALL)
                # Skip header
                next(csvReader)
                self.stored = []
                for row in csvReader:
                    self.stored.append(
                        (
                            row[1],   # BSSID
                            row[2]    # ESSID
                        )
                    )
        except FileNotFoundError:
            self.stored = []

    def iw_scanner(self):
        """Parsing iw scan results"""
        pass  # Implementation needed

    @staticmethod
    def handle_network(line, result, networks):
        pass  # Implementation needed

    @staticmethod
    def handle_essid(line, result, networks):
        pass  # Implementation needed

    @staticmethod
    def handle_level(line, result, networks):
        pass  # Implementation needed

    @staticmethod
    def handle_securityType(line, result, networks):
        pass  # Implementation needed

    @staticmethod
    def handle_wps(line, result, networks):
        pass  # Implementation needed

    @staticmethod
    def handle_wpsLocked(line, result, networks):
        pass  # Implementation needed

    @staticmethod
    def handle_model(line, result, networks):
        pass  # Implementation needed

    @staticmethod
    def handle_modelNumber(line, result, networks):
        pass  # Implementation needed

    @staticmethod
    def handle_deviceName(line, result, networks):
        pass  # Implementation needed

    @staticmethod
    def truncateStr(s, length, postfix='…'):
        """
        Truncate string with the specified length
        @s — input string
        @length — length of output string
        """
        if len(s) <= length:
            return s
        return s[:length-1] + postfix

    @staticmethod
    def colored(text, color=None):
        """Returns colored text"""
        colors = {
            'red': 31,
            'green': 32,
            'yellow': 33,
            'blue': 34,
            'magenta': 35,
            'cyan': 36,
            'grey': 37,
            'reset': 39
        }
        if color not in colors:
            return text
        return f"\033[{colors[color]}m{text}\033[{colors['reset']}m"

    def prompt_network(self):
        """Prompt user to select a network"""
        pass  # Implementation needed
