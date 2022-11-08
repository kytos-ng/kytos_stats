"""Utility classes and definitions."""
import struct


class IPv4AddressWithMask:
    """Class to represent an IPv4 address with netmask."""

    def __init__(self, address=0, netmask=0):
        """Instatiate with given ip address and netmask."""
        self.address = address
        self.netmask = netmask

    def __repr__(self):
        return f'<{self.__class__.__name__}: {self.as_dot_string()}>'

    def __str__(self):
        return self.as_dot_string()

    def as_dot_string(self):
        # pylint: disable=W0631
        """Represent an IPv4 address with mask as 0.0.0.0/0."""
        packed = struct.pack('!I', self.address)
        unpacked_bytes = struct.unpack('!4B', packed)
        address = '.'.join([str(x) for x in unpacked_bytes])
        for i in range(1, 33):
            stripped_mask = self.netmask >> i << i
            if stripped_mask != self.netmask:
                break
        mask = 33 - i
        return f'{address}/{mask}'

    def unpack(self, buffer, start=0):
        """Unpack IPv4 address and netmask."""
        self.address, self.netmask = struct.unpack('!2I',
                                                   buffer[start:start+8])


class IPv6AddressWithMask:
    """Class to represent an IPv6 address with netmask."""

    def __init__(self, address=0, netmask=0):
        """Instantiate with given ip address and netmask."""
        self.address = address
        self.netmask = netmask

    def __repr__(self):
        return f'<{self.__class__.__name__}: {self.as_comma_string()}>'

    def __str__(self):
        return self.as_comma_string()

    def as_comma_string(self):
        # pylint: disable=W0631
        """Represent an IPv6 address with mask as ffff::0/0."""
        address = []
        addrs = divmod(self.address, 2**64)
        for addr in addrs:
            packed = struct.pack('!Q', addr)
            unpacked_bytes = struct.unpack('!4H', packed)
            address.append(':'.join([f'{b:x}' for b in unpacked_bytes]))
        address = ':'.join(address)
        for i in range(1, 129):
            stripped_mask = self.netmask >> i << i
            if stripped_mask != self.netmask:
                break
        mask = 129 - i
        return f'{address}/{mask}'

    def unpack(self, buffer, start=0):
        """Unpack IPv6 address and mask."""
        self.address = int.from_bytes(buffer[start:start+16], 'big')
        self.netmask = int.from_bytes(buffer[start+16:start+32], 'big')
