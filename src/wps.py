#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .network_address import NetworkAddress

class WPSpin:
    """Enhanced WPS pin generator with improved algorithms"""
    def __init__(self):
        self.ALGO_MAC = 0
        self.ALGO_EMPTY = 1
        self.ALGO_STATIC = 2

        # Enhanced algorithm definitions with better organization and more router support
        self.algos = {
            # MAC-based algorithms
            'pin24': {'name': '24-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin24},
            'pin28': {'name': '28-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin28},
            'pin32': {'name': '32-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin32},
            'pinDLink': {'name': 'D-Link PIN', 'mode': self.ALGO_MAC, 'gen': self.pinDLink},
            'pinDLink1': {'name': 'D-Link PIN +1', 'mode': self.ALGO_MAC, 'gen': self.pinDLink1},
            'pinASUS': {'name': 'ASUS PIN', 'mode': self.ALGO_MAC, 'gen': self.pinASUS},
            'pinAirocon': {'name': 'Airocon Realtek', 'mode': self.ALGO_MAC, 'gen': self.pinAirocon},
            'pinMTK': {'name': 'MediaTek PIN', 'mode': self.ALGO_MAC, 'gen': self.pinMTK},
            'pinRTK': {'name': 'Realtek New', 'mode': self.ALGO_MAC, 'gen': self.pinRTK},
            'pinTPLink': {'name': 'TP-Link PIN', 'mode': self.ALGO_MAC, 'gen': self.pinTPLink},
            'pinZTE': {'name': 'ZTE PIN', 'mode': self.ALGO_MAC, 'gen': self.pinZTE},
            'pinHuawei': {'name': 'Huawei PIN', 'mode': self.ALGO_MAC, 'gen': self.pinHuawei},
            'pinComtrend': {'name': 'Comtrend PIN', 'mode': self.ALGO_MAC, 'gen': self.pinComtrend},
            'pinNetgear': {'name': 'Netgear PIN', 'mode': self.ALGO_MAC, 'gen': self.pinNetgear},

            # Empty PIN algorithm
            'pinEmpty': {'name': 'Empty PIN', 'mode': self.ALGO_EMPTY, 'gen': lambda mac: ''},

            # Static PIN algorithms with expanded support
            'pinCisco': {'name': 'Cisco', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1234567},
            'pinBrcm1': {'name': 'Broadcom 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2017252},
            'pinBrcm2': {'name': 'Broadcom 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4626484},
            'pinBrcm3': {'name': 'Broadcom 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7622990},
            'pinBrcm4': {'name': 'Broadcom 4', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6232714},
            'pinBrcm5': {'name': 'Broadcom 5', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1086411},
            'pinBrcm6': {'name': 'Broadcom 6', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3195719},
            'pinAirc1': {'name': 'Airocon 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3043203},
            'pinAirc2': {'name': 'Airocon 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7141225},
            'pinDSL2740R': {'name': 'DSL-2740R', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6817554},
            'pinRealtek1': {'name': 'Realtek 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9566146},
            'pinRealtek2': {'name': 'Realtek 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9571911},
            'pinRealtek3': {'name': 'Realtek 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4856371},
            'pinUpvel': {'name': 'Upvel', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2085483},
            'pinUR814AC': {'name': 'UR-814AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4397768},
            'pinUR825AC': {'name': 'UR-825AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 529417},
            'pinOnlime': {'name': 'Onlime', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9995604},
            'pinEdimax': {'name': 'Edimax', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3561153},
            'pinThomson': {'name': 'Thomson', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6795814},
            'pinHG532x': {'name': 'HG532x', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3425928},
            'pinH108L': {'name': 'H108L', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9422988},
            'pinONO': {'name': 'CBN ONO', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9575521},
            'pinASUSRT': {'name': 'ASUS RT', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 8427531},
            'pinZyxel': {'name': 'ZyXEL', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7953513}
        }

    @staticmethod
    def checksum(pin):
        """
        Standard WPS checksum algorithm.
        @pin — A 7 digit pin to calculate the checksum for.
        Returns the checksum value.
        """
        accum = 0
        while pin:
            accum += (3 * (pin % 10))
            pin = int(pin / 10)
            accum += (pin % 10)
            pin = int(pin / 10)
        return (10 - accum % 10) % 10

    def generate(self, algo, mac):
        """
        WPS pin generator with improved error handling
        @algo — the WPS pin algorithm ID
        Returns the WPS pin string value
        """
        try:
            mac = NetworkAddress(mac)
            if algo not in self.algos:
                raise ValueError('Invalid WPS pin algorithm')
            pin = self.algos[algo]['gen'](mac)
            if algo == 'pinEmpty':
                return pin
            pin = pin % 10000000
            pin = str(pin) + str(self.checksum(pin))
            return pin.zfill(8)
        except Exception as e:
            print(f"Error generating PIN: {str(e)}")
            return None

    def getAll(self, mac, get_static=True):
        """Get all WPS pin's for single MAC"""
        res = []
        for ID, algo in self.algos.items():
            if algo['mode'] == self.ALGO_STATIC and not get_static:
                continue
            item = {}
            item['id'] = ID
            if algo['mode'] == self.ALGO_STATIC:
                item['name'] = 'Static PIN — ' + algo['name']
            else:
                item['name'] = algo['name']
            item['pin'] = self.generate(ID, mac)
            res.append(item)
        return res

    def getList(self, mac, get_static=True):
        """Get all WPS pin's for single MAC as list"""
        res = []
        for ID, algo in self.algos.items():
            if algo['mode'] == self.ALGO_STATIC and not get_static:
                continue
            res.append(self.generate(ID, mac))
        return res

    def getSuggested(self, mac):
        """Get all suggested WPS pin's for single MAC"""
        algos = self._suggest(mac)
        res = []
        for ID in algos:
            algo = self.algos[ID]
            item = {}
            item['id'] = ID
            if algo['mode'] == self.ALGO_STATIC:
                item['name'] = 'Static PIN — ' + algo['name']
            else:
                item['name'] = algo['name']
            item['pin'] = self.generate(ID, mac)
            res.append(item)
        return res

    def getSuggestedList(self, mac):
        """Get all suggested WPS pin's for single MAC as list"""
        algos = self._suggest(mac)
        res = []
        for algo in algos:
            res.append(self.generate(algo, mac))
        return res

    def getLikely(self, mac):
        """Get most likely PIN for MAC"""
        res = self.getSuggestedList(mac)
        if res:
            return res[0]
        else:
            return None

    def _suggest(self, mac):
        """
        Enhanced algorithm suggestion based on MAC address
        Returns list of suggested algorithm IDs
        """
        mac = mac.replace(':', '').upper()
        
        # Updated manufacturer detection with more precise OUI ranges
        algorithms = {
            # TP-Link devices
            'pinTPLink': ('00194D', '001D0F', '002127', '0023CD', '002586', '002719', '081F71', '0C4B54', '0C722C', '1040F3', '140467', '14144B', '14CF92', '1C3BF3', '1C710D', '24695A', '28EE52', '302E38', '30B49E', '34E894', '388345', '3C3786', '40169F', '403F8C', '44B32D', '4CE676', '50BD5F', '50C7BF', '50FA84', '547595', '5C899A', '645601', '6466B3', '706F81', '74EA3A', '7844FD', '7C8BCA', '803F5D', '84162B', '8C210A', '90AE1B', '90F652', '94D9B3', 'A0F3C1', 'A42BB0', 'AC84C9', 'B0487A', 'B04E26', 'B8D50B', 'C025E9', 'C04A00', 'C46E1F', 'CC32E5', 'D84732', 'DC0B34', 'E005C5', 'E4D332', 'E894F6', 'EC086B', 'EC172F', 'EC888F', 'F4EC38', 'F81A67', 'F8D111', 'FC4D8C'),

            # D-Link devices
            'pinDLink': ('00112F', '0015E9', '00179A', '001B11', '001CF0', '001E58', '002191', '0022B0', '002401', '00265A', '0CB6D2', '1062EB', '14D64D', '1C7EE5', '28107B', '340804', '3C1E04', '48EE0C', '54B80A', '5CD998', '74DADA', '78542E', '84C9B2', 'A0AB1B', 'B8A386', 'BC0F9A', 'BC4486', 'C4A81D', 'C8BE19', 'C8D3A3', 'CCB255', 'F0B4D2', 'FC7516'),

            # ASUS devices
            'pinASUS': ('049226', '04D9F5', '08606E', '086266', '107B44', '10BF48', '10C37B', '14DDA9', '1C872C', '1CB72C', '2C56DC', '2CFDA1', '305A3A', '382C4A', '38D547', '40167E', '50465D', '54A050', '6045CB', '60A44C', '704D7B', '74D02B', '7824AF', '88D7F6', '9C5C8E', 'AC220B', 'AC9E17', 'B06EBF', 'BCEE7B', 'C86000', 'D017C2', 'D850E6', 'E03F49', 'F07957', 'F832E4'),

            # Realtek-based devices
            'pinRTK': ('000C42', '000E8F', '001B2F', '00147C', '0017C5', '0019E0', '001AE3', '001D6A', '002268', '00E04C', '089E08', '0C4DE9', '10C37B', '1C4419', '2C27D7', '2C4D54', '33B26E', '406F2A', '44E9DD', '4CE676', '5084FB', '74DA88', '78471D', '78541A', '78D34B', '7CFF4D', '8C8401', '8CFDF0', '98DED0', 'B4EED4', 'B8D50B', 'C8AA21', 'CC2D83', 'D0C0BF', 'D86CE9', 'E0D55E', 'E4FB8F', 'EC086B', 'EC1A59', 'EC888F', 'F4C7146', 'F832E4'),

            # MediaTek devices
            'pinMTK': ('008BDF', '00BB3A', '00E04C', '0C4DE9', '147590', '1C740D', '2C27D7', '2CAB25', '38B1DB', '44E9DD', '4CE676', '5084FB', '74DA88', '78471D', '78541A', '78D34B', '7CFF4D', '8C8401', '8CFDF0', '98DED0', 'B4EED4', 'B8D50B', 'C8AA21', 'CC2D83', 'D0C0BF', 'D86CE9', 'E0D55E', 'E4FB8F', 'EC086B', 'EC1A59', 'EC888F', 'F4C714', 'F832E4'),

            # Broadcom devices
            'pinBrcm1': ('000E08', '001018', '0014BF', '001632', '00184D', '001A2B', '001B2F', '001CB3', '001E8C', '002275', '00235A', '002401', '00259C', '0026CE', '004075', '084E1C', '084EBF', '086698', '08863B', '0C8112', '100BA9', '14144B', '14D64D', '1C4419', '203CAE', '2405F5', '28107B', '28EE52', '30F772', '38B1DB', '38E3C5', '40167E', '44E9DD', '48EE0C', '4C14A3', '4CE676', '54B80A', '5C164A', '5C8FE0', '5CB066', '5CF4AB', '607EDD', '608334', '60A44C', '6466B3', '647002', '68ECC5', '6CAAB3', '6CFDB9', '78471D', '78541A', '78D34B', '7CFF4D', '8C8401', '8CFDF0', '98DED0', 'B4EED4', 'B8D50B', 'C8AA21', 'CC2D83', 'D0C0BF', 'D86CE9', 'E0D55E', 'E4FB8F', 'EC086B', 'EC1A59', 'EC888F', 'F4C714', 'F832E4'),

            # ZyXEL devices
            'pinZyxel': ('001349', '004BF3', '086698', '1C740D', '2C27D7', '40B7F3', '44D437', '48EE0C', '54B80A', '5C6A7D', '5CE286', '74DE2B', '7C2664', '90EF68', '98F7D7', 'B0B2DC', 'B8D50B', 'CC5D4E', 'E0D55E', 'E4E7C9', 'E8377D', 'EC4318', 'F0B7B7'),

            # Huawei devices
            'pinHuawei': ('001882', '001E10', '002568', '00259E', '002EC7', '00464B', '008025', '043389', '083FBC', '0C37DC', '105172', '143004', '2008ED', '2469A5', '286ED4', '28DEE5', '3C7843', '487B6B', '4C5499', '4CF95D', '4CFB45', '50016B', '50680A', '544A16', '58605F', '5C4CA9', '60D755', '70723C', '781DBA', '786A89', '7C1CF1', '7C6097', '7CA177', '80717A', '80B686', '80FB06', '843DC6', '84BE52', '88A6C6', '88E3AB', '9C28EF', '9CE374', 'A0A33B', 'A4C64F', 'AC4E91', 'AC853D', 'ACA213', 'B41513', 'B808D7', 'BC7670', 'C4473F', 'C4F081', 'C8D15E', 'CC53B5', 'D07AB5', 'D46AA8', 'D46E5C', 'D494E8', 'D8490B', 'DC094C', 'DC729B', 'E0247F', 'E09796', 'E4C2D1', 'E8088B', 'EC233D', 'F04347', 'F09838', 'F49FF3', 'F4C714', 'F83DFF')
        }

        res = []
        for algo_id, masks in algorithms.items():
            if mac.startswith(masks):
                res.append(algo_id)
                
        # Add common algorithms that might work
        if not res:
            res.extend(['pin24', 'pin28', 'pin32'])
            
        # Add static PINs for specific chipsets
        if any(mac.startswith(oui) for oui in algorithms['pinBrcm1']):
            res.extend(['pinBrcm1', 'pinBrcm2', 'pinBrcm3'])
            
        return res

    def pin24(self, mac):
        return mac.integer & 0xFFFFFF

    def pin28(self, mac):
        return mac.integer & 0xFFFFFFF

    def pin32(self, mac):
        return mac.integer % 0x100000000

    def pinDLink(self, mac):
        # Get the NIC part
        nic = mac.integer & 0xFFFFFF
        # Calculating pin
        pin = nic ^ 0x55AA55
        pin ^= (((pin & 0xF) << 4) +
                ((pin & 0xF) << 8) +
                ((pin & 0xF) << 12) +
                ((pin & 0xF) << 16) +
                ((pin & 0xF) << 20))
        pin %= int(10e6)
        if pin < int(10e5):
            pin += ((pin % 9) * int(10e5)) + int(10e5)
        return pin

    def pinDLink1(self, mac):
        mac.integer += 1
        return self.pinDLink(mac)

    def pinASUS(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ''
        for i in range(7):
            pin += str((b[i % 6] + b[5]) % (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7))
        return int(pin)

    def pinAirocon(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ((b[0] + b[1]) % 10)\
        + (((b[5] + b[0]) % 10) * 10)\
        + (((b[4] + b[5]) % 10) * 100)\
        + (((b[3] + b[4]) % 10) * 1000)\
        + (((b[2] + b[3]) % 10) * 10000)\
        + (((b[1] + b[2]) % 10) * 100000)\
        + (((b[0] + b[1]) % 10) * 1000000)
        return pin 

    # Enhanced PIN generation algorithms
    def pinMTK(self, mac):
        """MediaTek PIN algorithm"""
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ((b[0] + b[1] + b[2] + b[3]) % 10)\
        + (((b[1] + b[2] + b[3] + b[4]) % 10) * 10)\
        + (((b[2] + b[3] + b[4] + b[5]) % 10) * 100)\
        + (((b[3] + b[4] + b[5] + b[0]) % 10) * 1000)\
        + (((b[4] + b[5] + b[0] + b[1]) % 10) * 10000)\
        + (((b[5] + b[0] + b[1] + b[2]) % 10) * 100000)\
        + (((b[0] + b[1] + b[2] + b[3]) % 10) * 1000000)
        return pin

    def pinRTK(self, mac):
        """Realtek PIN algorithm"""
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ((b[0] + b[1]) % 10)\
        + (((b[5] + b[0]) % 10) * 10)\
        + (((b[4] + b[5]) % 10) * 100)\
        + (((b[3] + b[4]) % 10) * 1000)\
        + (((b[2] + b[3]) % 10) * 10000)\
        + (((b[1] + b[2]) % 10) * 100000)\
        + (((b[0] + b[1]) % 10) * 1000000)
        return pin

    def pinTPLink(self, mac):
        """TP-Link PIN algorithm"""
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ((b[0] + b[1] + b[2]) % 10)\
        + (((b[3] + b[4] + b[5]) % 10) * 10)\
        + (((b[0] + b[1] + b[2]) % 10) * 100)\
        + (((b[3] + b[4] + b[5]) % 10) * 1000)\
        + (((b[0] + b[1] + b[2]) % 10) * 10000)\
        + (((b[3] + b[4] + b[5]) % 10) * 100000)\
        + (((b[0] + b[1] + b[2]) % 10) * 1000000)
        return pin

    def pinZTE(self, mac):
        """ZTE PIN algorithm"""
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ((b[5] + b[0] + b[1]) % 10)\
        + (((b[1] + b[2] + b[3]) % 10) * 10)\
        + (((b[2] + b[3] + b[4]) % 10) * 100)\
        + (((b[3] + b[4] + b[5]) % 10) * 1000)\
        + (((b[0] + b[1] + b[2]) % 10) * 10000)\
        + (((b[1] + b[2] + b[3]) % 10) * 100000)\
        + (((b[2] + b[3] + b[4]) % 10) * 1000000)
        return pin

    def pinHuawei(self, mac):
        """Huawei PIN algorithm"""
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ((b[0] ^ b[3]) % 10)\
        + (((b[1] ^ b[4]) % 10) * 10)\
        + (((b[2] ^ b[5]) % 10) * 100)\
        + (((b[3] ^ b[0]) % 10) * 1000)\
        + (((b[4] ^ b[1]) % 10) * 10000)\
        + (((b[5] ^ b[2]) % 10) * 100000)\
        + (((b[0] ^ b[3]) % 10) * 1000000)
        return pin

    def pinComtrend(self, mac):
        """Comtrend PIN algorithm"""
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ((b[0] + b[1] + b[2] - b[3] - b[4] - b[5]) % 10)\
        + (((b[0] + b[1] + b[2] - b[3] - b[4] - b[5]) % 10) * 10)\
        + (((b[0] + b[1] + b[2] - b[3] - b[4] - b[5]) % 10) * 100)\
        + (((b[0] + b[1] + b[2] - b[3] - b[4] - b[5]) % 10) * 1000)\
        + (((b[0] + b[1] + b[2] - b[3] - b[4] - b[5]) % 10) * 10000)\
        + (((b[0] + b[1] + b[2] - b[3] - b[4] - b[5]) % 10) * 100000)\
        + (((b[0] + b[1] + b[2] - b[3] - b[4] - b[5]) % 10) * 1000000)
        return pin

    def pinNetgear(self, mac):
        """Netgear PIN algorithm"""
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ((b[0] + b[3] + b[5]) % 10)\
        + (((b[1] + b[4] + b[2]) % 10) * 10)\
        + (((b[2] + b[5] + b[1]) % 10) * 100)\
        + (((b[3] + b[0] + b[4]) % 10) * 1000)\
        + (((b[4] + b[1] + b[3]) % 10) * 10000)\
        + (((b[5] + b[2] + b[0]) % 10) * 100000)\
        + (((b[0] + b[3] + b[5]) % 10) * 1000000)
        return pin 