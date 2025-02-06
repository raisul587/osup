"""
Modern vendor-specific WPS PIN generation algorithms (2023-2025 models)
"""
from src.utils.network import NetworkAddress

class ModernVendorPins:
    @staticmethod
    def tp_link_2023(mac: NetworkAddress) -> int:
        """TP-Link 2023-2025 models PIN generation"""
        mac_bytes = [int(x, 16) for x in [mac.hex[i:i+2] for i in range(0, 12, 2)]]
        pin = ((mac_bytes[0] << 24) + (mac_bytes[1] << 16) + (mac_bytes[2] << 8) + mac_bytes[3]) % 10000000
        return pin

    @staticmethod
    def xiaomi_aiot(mac: NetworkAddress) -> int:
        """Xiaomi AIoT Router PIN generation (AX3000T, AX6000, AX9000)"""
        mac_str = mac.hex
        seed = int(mac_str[-6:], 16)
        pin = ((seed * 0x3b) ^ 0x1234567) % 10000000
        return pin

    @staticmethod
    def asus_ax(mac: NetworkAddress) -> int:
        """ASUS 2023+ AX series routers"""
        mac_bytes = [int(x, 16) for x in [mac.hex[i:i+2] for i in range(0, 12, 2)]]
        pin = ((mac_bytes[5] << 15) + (mac_bytes[1] << 10) + (mac_bytes[2] << 5) + mac_bytes[3]) % 10000000
        return pin

    @staticmethod
    def netgear_nx(mac: NetworkAddress) -> int:
        """Netgear Nighthawk 2023+ series"""
        mac_int = int(mac.hex, 16)
        pin = ((mac_int & 0xFFFFFF) ^ (mac_int >> 24)) % 10000000
        return pin

    @staticmethod
    def huawei_ax(mac: NetworkAddress) -> int:
        """Huawei WiFi AX3/AX2 Pro series"""
        mac_bytes = [int(x, 16) for x in [mac.hex[i:i+2] for i in range(0, 12, 2)]]
        pin = ((mac_bytes[0] + mac_bytes[5]) << 24) % 10000000
        return pin

    @staticmethod
    def mercusys_2023(mac: NetworkAddress) -> int:
        """Mercusys 2023+ models (ME70X, ME100X series)"""
        mac_str = mac.hex
        seed = int(mac_str[-8:], 16)
        pin = (seed ^ 0x7A12F64E) % 10000000
        return pin
