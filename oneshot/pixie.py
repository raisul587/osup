#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class PixiewpsData:
    def __init__(self):
        self.pke = ''
        self.pkr = ''
        self.e_hash1 = ''
        self.e_hash2 = ''
        self.authkey = ''
        self.e_nonce = ''

    def clear(self):
        self.__init__()

    def got_all(self):
        return (self.pke and self.pkr and self.e_hash1 and
                self.e_hash2 and self.authkey and self.e_nonce)

    def get_pixie_cmd(self, full_range=False):
        # Build pixiewps command
        cmd = ['pixiewps']
        cmd.append('--pke {}'.format(self.pke))
        cmd.append('--pkr {}'.format(self.pkr))
        cmd.append('--e-hash1 {}'.format(self.e_hash1))
        cmd.append('--e-hash2 {}'.format(self.e_hash2))
        cmd.append('--authkey {}'.format(self.authkey))
        cmd.append('--e-nonce {}'.format(self.e_nonce))
        if full_range:
            cmd.append('--force')
        return ' '.join(cmd)
