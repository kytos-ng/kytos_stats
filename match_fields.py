"""OpenFlow 1.3 OXM match fields.

Some OpenFlow 1.3 fields not yet implemented by
Kytos but necessary for this NApp.
"""
from napps.amlight.flow_stats.utils import (IPv4AddressWithMask,
                                                    IPv6AddressWithMask)
from napps.kytos.of_core.v0x04.match_fields import MatchField
from pyof.foundation.basic_types import HWAddress
from pyof.v0x04.common.flow_match import OxmOfbMatchField, OxmTLV, VlanId


class MatchIPv6Src(MatchField):
    """Match for IPv6 source."""

    name = 'ipv6_src'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_IPV6_SRC

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = self.value.to_bytes(16, 'big')
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        ip_address = IPv6AddressWithMask()
        ip_address.unpack(tlv.oxm_value)
        return cls(ip_address)


class MatchIPv6Dst(MatchField):
    """Match for IPv6 destination."""

    name = 'ipv6_dst'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_IPV6_DST

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = self.value.to_bytes(16, 'big')
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        ip_address = IPv6AddressWithMask()
        ip_address.unpack(tlv.oxm_value)
        return cls(ip_address)


class MatchIPv4Src(MatchField):
    """Match for IPv4 source."""

    name = 'ipv4_src'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_IPV4_SRC

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = self.value.to_bytes(4, 'big')
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        ip_address = IPv4AddressWithMask()
        ip_address.unpack(tlv.oxm_value)
        return cls(ip_address)


class MatchIPv4Dst(MatchField):
    """Match for IPv4 destination."""

    name = 'ipv4_dst'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_IPV4_DST

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = self.value.to_bytes(4, 'big')
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        ip_address = IPv4AddressWithMask()
        ip_address.unpack(tlv.oxm_value)
        return cls(ip_address)


class MatchVlanVid(MatchField):
    """Match for VLAN id."""

    name = 'vlan_vid'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_VLAN_VID

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value = self.value | VlanId.OFPVID_PRESENT
        value_bytes = value.to_bytes(2, 'big')
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        vlan_id = int.from_bytes(tlv.oxm_value, 'big') & 4095
        return cls(vlan_id)


class MatchVlanPCP(MatchField):
    """Match for VLAN Priority Code Point."""

    name = 'vlan_pcp'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_VLAN_PCP

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = self.value.to_bytes(1, 'big')
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        priority = int.from_bytes(tlv.oxm_value, 'big')
        return cls(priority)


class MatchEthSrc(MatchField):
    """Match for ethernet address source."""

    name = 'eth_src'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_ETH_SRC

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = HWAddress(self.value).pack()
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        hw_address = HWAddress()
        hw_address.unpack(tlv.oxm_value)
        addr_str = str(hw_address)
        return cls(addr_str)


class MatchEthDst(MatchField):
    """Match for ethernet address destination."""

    name = 'eth_dst'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_ETH_DST

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = HWAddress(self.value).pack()
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        hw_address = HWAddress()
        hw_address.unpack(tlv.oxm_value)
        addr_str = str(hw_address)
        return cls(addr_str)


class MatchEthType(MatchField):
    """Match for ethernet type."""

    name = 'eth_type'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_ETH_TYPE

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = self.value.to_bytes(2, 'big')
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        port = int.from_bytes(tlv.oxm_value, 'big')
        return cls(port)


class MatchIPProto(MatchField):
    """Match for IP protocol."""

    name = 'ip_proto'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_IP_PROTO

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = self.value.to_bytes(1, 'big')
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        priority = int.from_bytes(tlv.oxm_value, 'big')
        return cls(priority)


class MatchTCPSrc(MatchField):
    """Match for TCP source port."""

    name = 'tcp_src'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_TCP_SRC

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = self.value.to_bytes(2, 'big')
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        port = int.from_bytes(tlv.oxm_value, 'big')
        return cls(port)


class MatchTCPDst(MatchField):
    """Match for TCP destination port."""

    name = 'tcp_dst'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_TCP_DST

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = self.value.to_bytes(2, 'big')
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        port = int.from_bytes(tlv.oxm_value, 'big')
        return cls(port)


class MatchUDPSrc(MatchField):
    """Match for UDP source port."""

    name = 'udp_src'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_UDP_SRC

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = self.value.to_bytes(2, 'big')
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        port = int.from_bytes(tlv.oxm_value, 'big')
        return cls(port)


class MatchUDPDst(MatchField):
    """Match for UDP source port."""

    name = 'udp_dst'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_UDP_DST

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = self.value.to_bytes(2, 'big')
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        port = int.from_bytes(tlv.oxm_value, 'big')
        return cls(port)


class MatchARPOp(MatchField):
    """Match for ARP opcode."""

    name = 'arp_op'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_ARP_OP

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = self.value.to_bytes(2, 'big')
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        opcode = int.from_bytes(tlv.oxm_value, 'big')
        return cls(opcode)


class MatchMPLSLabel(MatchField):
    """Match for MPLS label."""

    name = 'mpls_label'
    oxm_field = OxmOfbMatchField.OFPXMT_OFB_MPLS_LABEL

    def as_of_tlv(self):
        """Return a pyof OXM TLV instance."""
        value_bytes = self.value.to_bytes(3, 'big')
        return OxmTLV(oxm_field=self.oxm_field, oxm_value=value_bytes)

    @classmethod
    def from_of_tlv(cls, tlv):
        """Return an instance from a pyof OXM TLV."""
        label = int.from_bytes(tlv.oxm_value, 'big')
        return cls(label)
