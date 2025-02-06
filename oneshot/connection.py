#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
import collections
import time

class ConnectionStatus:
    def __init__(self):
        self.status = ''   # Must be WSC_NACK, WPS_FAIL or GOT_PSK
        self.last_m_message = 0
        self.essid = ''
        self.wpa_psk = ''

    def isFirstHalfValid(self):
        return self.last_m_message > 5

    def clear(self):
        self.__init__()

class BruteforceStatus:
    def __init__(self):
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.mask = ''
        self.last_attempt_time = time.time()   # Last PIN attempt start time
        self.attempts_times = collections.deque(maxlen=15)

        self.counter = 0
        self.statistics_period = 5

    def display_status(self):
        """Display current bruteforce status"""
        average_time = 0.0
        if len(self.attempts_times):
            average_time = sum(self.attempts_times) / len(self.attempts_times)
        if len(self.attempts_times) >= 5:
            message = (
                f"[*] {self.mask}: {self.counter} PINs tested, "
                f"average speed: {1 / average_time:.2f} pins/sec"
            )
        else:
            message = f"[*] {self.mask}: {self.counter} PINs tested"
        return message

    def registerAttempt(self, mask):
        self.counter += 1
        self.mask = mask
        current_time = time.time()
        self.attempts_times.append(current_time - self.last_attempt_time)
        self.last_attempt_time = current_time

    def clear(self):
        self.__init__()
