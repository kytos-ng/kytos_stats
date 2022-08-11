"""Module to test the utils.py file."""
from unittest import TestCase

from napps.amlight.flow_stats.utils import (
    IPv4AddressWithMask, IPv6AddressWithMask)


# pylint: disable=too-many-public-methods, too-many-lines
class TestIPv4AddressWithMask(TestCase):
    """Tests for the class IPv4AddressWithMask"""

    def test_ipv4(self):
        """Test IPv4 address."""
        ipv4 = IPv4AddressWithMask(address=3232235521)
        self.assertEqual(ipv4.as_dot_string(), "192.168.0.1/1")

    def test_ipv4_default(self):
        """Test IPv4 address with default values."""
        ipv4 = IPv4AddressWithMask()
        self.assertEqual(ipv4.as_dot_string(), "0.0.0.0/1")

    def test_ipv4_mask_zero(self):
        """Test IPv4 address with 0 netmask"""
        ipv4_mask_zero = IPv4AddressWithMask(address=3232235521, netmask=0)
        self.assertEqual(ipv4_mask_zero.as_dot_string(), "192.168.0.1/1")

    def test_ipv4_with_mask(self):
        """Test IPv4 address with address and mask."""
        ipv4 = IPv4AddressWithMask(address=3232235521, netmask=1)
        self.assertEqual(ipv4.as_dot_string(), "192.168.0.1/32")


# pylint: disable=too-many-public-methods, too-many-lines
class TestIPv6AddressWithMask(TestCase):
    """Tests for the class IPv6AddressWithMask"""
    def test_ipv6(self):
        """Test IPv6 address."""
        ipv6 = IPv6AddressWithMask(address=3232235521)
        self.assertEqual(ipv6.as_comma_string(), "0:0:0:0:0:0:c0a8:1/1")

    def test_ipv6_default(self):
        """Test IPv4 address with default values."""
        ipv6 = IPv6AddressWithMask()
        self.assertEqual(ipv6.as_comma_string(), "0:0:0:0:0:0:0:0/1")

    def test_ipv6_mask_zero(self):
        """Test IPv6 address with netmask 0."""
        ipv6_mask_zero = IPv6AddressWithMask(address=3232235521, netmask=0)
        self.assertEqual(ipv6_mask_zero.as_comma_string(),
                         "0:0:0:0:0:0:c0a8:1/1")

    def test_ipv6_with_mask(self):
        """Test IPv6 address with address and mask."""
        ipv6 = IPv6AddressWithMask(address=3232235521, netmask=1)
        self.assertEqual(ipv6.as_comma_string(), "0:0:0:0:0:0:c0a8:1/128")
