"""Main module of amlight/kytos_flow_manager Kytos Network Application.

# TODO: <<<< Insert here your NApp description >>>>
"""

from kytos.core import KytosNApp, log, rest
from kytos.core.switch import Switch
from kytos.core.helpers import listen_to
from napps.amlight.sdntrace import constants
from napps.amlight.sdntrace.shared.switches import Switches
from napps.amlight.kytos_flow_manager.utils import Flows, ACTION_TYPES
from napps.amlight.sdntrace.shared.extd_nw_types import VLAN, TCP, UDP
from napps.amlight.kytos_flow_manager import settings
from pyof.v0x01.common.flow_match import FlowWildCards
from pyof.v0x01.common.action import ActionType
from pyof.v0x01.controller2switch.flow_mod import FlowMod as FlowMod10
from pyof.v0x04.controller2switch.flow_mod import FlowMod as FlowMod13
from pyof.foundation.network_types import Ethernet, IPv4
import pyof.v0x01.controller2switch.common as common01
from collections import defaultdict
import weakref
from flask import request, jsonify
import json, dill
import ipaddress
import hashlib


class GenericFlow(object):
    def __init__(self, version=0x01, in_port=0, phy_port=None, eth_src=None,
                 eth_dst=None, eth_type=None, vlan_vid=None, vlan_pcp=None,
                 ip_tos=None, ip_dscp=None, ip_ecn=None, ip_proto=None,
                 ipv4_src=None, ipv4_dst=None, ipv6_src=None, ipv6_dst=None,
                 tcp_src=None, tcp_dst=None, udp_src=None, udp_dst=None,
                 sctp_src=None, sctp_dst=None, icmpv4_type=None,
                 icmpv4_code=None, arp_op=None, arp_spa=None, arp_tpa=None,
                 arp_sha=None, arp_tha=None, ipv6_flabel=None, icmpv6_type=None,
                 icmpv6_code=None, ipv6_nd_target=None, ipv6_nd_sll=None,
                 ipv6_nd_tll=None, mpls_label=None, mpls_tc=None, mpls_bos=None,
                 pbb_isid=None, tunnel_id=None, ipv6_exthdr=None,
                 wildcards=None, idle_timeout=0, hard_timeout=0, duration_sec=0,
                 packet_count=0, byte_count=0, priority=0, table_id=0xff,
                 cookie=None, buffer_id=None, actions=None):
        self.version = version
        self.in_port = in_port
        self.phy_port = phy_port
        self.eth_src = eth_src
        self.eth_dst = eth_dst
        self.eth_type = eth_type
        self.vlan_vid = vlan_vid
        self.vlan_pcp = vlan_pcp
        self.ip_tos = ip_tos
        self.ip_dscp = ip_dscp
        self.ip_ecn = ip_ecn
        self.ip_proto = ip_proto
        self.ipv4_src = ipv4_src
        self.ipv4_dst = ipv4_dst
        self.ipv6_src = ipv6_src
        self.ipv6_dst = ipv6_dst
        self.tcp_src = tcp_src
        self.tcp_dst = tcp_dst
        self.udp_src = udp_src
        self.udp_dst = udp_dst
        self.sctp_src = sctp_src
        self.sctp_dst = sctp_dst
        self.icmpv4_type = icmpv4_type
        self.icmpv4_code = icmpv4_code
        self.arp_op = arp_op
        self.arp_spa = arp_spa
        self.arp_tpa = arp_tpa
        self.arp_sha = arp_sha
        self.arp_tha = arp_tha
        self.ipv6_flabel = ipv6_flabel
        self.icmpv6_type = icmpv6_type
        self.icmpv6_code = icmpv6_code
        self.ipv6_nd_target = ipv6_nd_target
        self.ipv6_nd_sll = ipv6_nd_sll
        self.ipv6_nd_tll = ipv6_nd_tll
        self.mpls_label = mpls_label
        self.mpls_tc = mpls_tc
        self.mpls_bos = mpls_bos
        self.pbb_isid = pbb_isid
        self.tunnel_id = tunnel_id
        self.ipv6_exthdr = ipv6_exthdr
        self.wildcards = wildcards
        self.idle_timeout = idle_timeout
        self.hard_timeout = hard_timeout
        self.duration_sec = duration_sec
        self.packet_count = packet_count
        self.byte_count = byte_count
        self.priority = priority
        self.table_id = table_id
        self.cookie = cookie
        self.buffer_id = buffer_id
        self.actions = actions

    @property
    def id(self):
        """Return the hash of the object.
        Calculates the hash of the object by using the hashlib we use md5 of
        strings.
        Returns:
            string: Hash of object.
        """
        hash_result = hashlib.md5()
        hash_result.update(str(self.version).encode('utf-8'))
        hash_result.update(str(self.in_port).encode('utf-8'))
        hash_result.update(str(self.phy_port).encode('utf-8'))
        hash_result.update(str(self.eth_src).encode('utf-8'))
        hash_result.update(str(self.eth_dst).encode('utf-8'))
        hash_result.update(str(self.eth_type).encode('utf-8'))
        hash_result.update(str(self.vlan_vid).encode('utf-8'))
        hash_result.update(str(self.vlan_pcp).encode('utf-8'))
        hash_result.update(str(self.ip_tos).encode('utf-8'))
        hash_result.update(str(self.ip_dscp).encode('utf-8'))
        hash_result.update(str(self.ip_ecn).encode('utf-8'))
        hash_result.update(str(self.ip_proto).encode('utf-8'))
        hash_result.update(str(self.ipv4_src).encode('utf-8'))
        hash_result.update(str(self.ipv4_dst).encode('utf-8'))
        hash_result.update(str(self.ipv6_src).encode('utf-8'))
        hash_result.update(str(self.ipv6_dst).encode('utf-8'))
        hash_result.update(str(self.tcp_src).encode('utf-8'))
        hash_result.update(str(self.tcp_dst).encode('utf-8'))
        hash_result.update(str(self.udp_src).encode('utf-8'))
        hash_result.update(str(self.udp_dst).encode('utf-8'))
        hash_result.update(str(self.sctp_src).encode('utf-8'))
        hash_result.update(str(self.sctp_dst).encode('utf-8'))
        hash_result.update(str(self.icmpv4_type).encode('utf-8'))
        hash_result.update(str(self.icmpv4_code).encode('utf-8'))
        hash_result.update(str(self.arp_op).encode('utf-8'))
        hash_result.update(str(self.arp_spa).encode('utf-8'))
        hash_result.update(str(self.arp_tpa).encode('utf-8'))
        hash_result.update(str(self.arp_sha).encode('utf-8'))
        hash_result.update(str(self.arp_tha).encode('utf-8'))
        hash_result.update(str(self.ipv6_flabel).encode('utf-8'))
        hash_result.update(str(self.icmpv6_type).encode('utf-8'))
        hash_result.update(str(self.icmpv6_code).encode('utf-8'))
        hash_result.update(str(self.ipv6_nd_target).encode('utf-8'))
        hash_result.update(str(self.ipv6_nd_sll).encode('utf-8'))
        hash_result.update(str(self.ipv6_nd_tll).encode('utf-8'))
        hash_result.update(str(self.mpls_label).encode('utf-8'))
        hash_result.update(str(self.mpls_tc).encode('utf-8'))
        hash_result.update(str(self.mpls_bos).encode('utf-8'))
        hash_result.update(str(self.pbb_isid).encode('utf-8'))
        hash_result.update(str(self.tunnel_id).encode('utf-8'))
        hash_result.update(str(self.ipv6_exthdr).encode('utf-8'))
        hash_result.update(str(self.wildcards).encode('utf-8'))
        hash_result.update(str(self.idle_timeout).encode('utf-8'))
        hash_result.update(str(self.hard_timeout).encode('utf-8'))
        hash_result.update(str(self.priority).encode('utf-8'))
        hash_result.update(str(self.table_id).encode('utf-8'))
        hash_result.update(str(self.cookie).encode('utf-8'))
        hash_result.update(str(self.buffer_id).encode('utf-8'))

        return hash_result.hexdigest()

    def to_dict(self):
        flow_dict = {}
        flow_dict['version'] = self.version
        flow_dict['in_port'] = self.in_port
        flow_dict['phy_port'] = self.phy_port
        flow_dict['eth_src'] = self.eth_src
        flow_dict['eth_dst'] = self.eth_dst
        flow_dict['eth_type'] = self.eth_type
        flow_dict['vlan_vid'] = self.vlan_vid
        flow_dict['vlan_pcp'] = self.vlan_pcp
        flow_dict['ip_tos'] = self.ip_tos
        flow_dict['ip_dscp'] = self.ip_dscp
        flow_dict['ip_ecn'] = self.ip_ecn
        flow_dict['ip_proto'] = self.ip_proto
        flow_dict['ipv4_src'] = self.ipv4_src
        flow_dict['ipv4_dst'] = self.ipv4_dst
        flow_dict['ipv6_src'] = self.ipv6_src
        flow_dict['ipv6_dst'] = self.ipv6_dst
        flow_dict['tcp_src'] = self.tcp_src
        flow_dict['tcp_dst'] = self.tcp_dst
        flow_dict['udp_src'] = self.udp_src
        flow_dict['udp_dst'] = self.udp_dst
        flow_dict['sctp_src'] = self.sctp_src
        flow_dict['sctp_dst'] = self.sctp_dst
        flow_dict['icmpv4_type'] = self.icmpv4_type
        flow_dict['icmpv4_code'] = self.icmpv4_code
        flow_dict['arp_op'] = self.arp_op
        flow_dict['arp_spa'] = self.arp_spa
        flow_dict['arp_tpa'] = self.arp_tpa
        flow_dict['arp_sha'] = self.arp_sha
        flow_dict['arp_tha'] = self.arp_tha
        flow_dict['ipv6_flabel'] = self.ipv6_flabel
        flow_dict['icmpv6_type'] = self.icmpv6_type
        flow_dict['icmpv6_code'] = self.icmpv6_code
        flow_dict['ipv6_nd_target'] = self.ipv6_nd_target
        flow_dict['ipv6_nd_sll'] = self.ipv6_nd_sll
        flow_dict['ipv6_nd_tll'] = self.ipv6_nd_tll
        flow_dict['mpls_label'] = self.mpls_label
        flow_dict['mpls_tc'] = self.mpls_tc
        flow_dict['mpls_bos'] = self.mpls_bos
        flow_dict['pbb_isid'] = self.pbb_isid
        flow_dict['tunnel_id'] = self.tunnel_id
        flow_dict['ipv6_exthdr'] = self.ipv6_exthdr
        flow_dict['wildcards'] = self.wildcards
        flow_dict['idle_timeout'] = self.idle_timeout
        flow_dict['hard_timeout'] = self.hard_timeout
        flow_dict['priority'] = self.priority
        flow_dict['table_id'] = self.table_id
        flow_dict['cookie'] = self.cookie
        flow_dict['buffer_id'] = self.buffer_id
        flow_dict['actions'] = []
        for action in self.actions:
            action_dict = {}
            for attr_key, attr_value in action.__dict__.items():
                action_dict[attr_key] = '%s' % attr_value
            flow_dict['actions'].append(action_dict)

        return flow_dict

    def to_json(self):
        return json.dumps(self.to_dict())

    @staticmethod
    def from_dict(flow_dict):
        flow = GenericFlow()
        for attr_name, value in flow_dict.items():
            if attr_name == 'actions':
                flow.actions = []
                for action in value:
                    new_action = ACTION_TYPES[int(action['action_type'])]()
                    for action_attr_name, action_attr_value in action.items():
                        setattr(new_action, action_attr_name, action_attr_value)
                    flow.actions.append(new_action)
            else:
                setattr(flow, attr_name, value)
        return flow

    @classmethod
    def from_flow_stats(cls, flow_stats, version=0x01):
        flow = GenericFlow(version=version)
        if version == 0x01:
            flow.idle_timeout = flow_stats.idle_timeout.value
            flow.hard_timeout = flow_stats.hard_timeout.value
            flow.priority = flow_stats.priority.value
            flow.table_id = flow_stats.table_id.value
            flow.wildcards = flow_stats.match.wildcards.value
            flow.in_port = flow_stats.match.in_port.value
            flow.eth_src = flow_stats.match.dl_src.value
            flow.eth_dst = flow_stats.match.dl_dst.value
            flow.vlan_vid = flow_stats.match.dl_vlan.value
            flow.vlan_pcp = flow_stats.match.dl_vlan_pcp.value
            flow.eth_type = flow_stats.match.dl_type.value
            flow.ip_tos = flow_stats.match.nw_tos.value
            flow.ipv4_src = flow_stats.match.nw_src.value
            flow.ipv4_dst = flow_stats.match.nw_dst.value
            flow.tcp_src = flow_stats.match.tp_src.value
            flow.tcp_dst = flow_stats.match.tp_dst.value
            flow.duration_sec = flow_stats.duration_sec.value
            flow.packet_count = flow_stats.packet_count.value
            flow.byte_count = flow_stats.byte_count.value
            flow.actions = []
            for action in flow_stats.actions:
                flow.actions.append(action)
        return flow

    def match(self, args):
        if self.version == 0x01:
            return self.match10(args)
        elif self.version == 0x04:
            return self.match13(args)

    def match10(self, args):
        log.debug('Matching packet')
        if not self.wildcards & FlowWildCards.OFPFW_IN_PORT:
            if 'in_port' not in args:
                return False
            if self.in_port != int(args['in_port']):
                return False
        if not self.wildcards & FlowWildCards.OFPFW_DL_VLAN_PCP:
            if 'vlan_pcp' not in args:
                return False
            if self.vlan_pcp != int(args['vlan_pcp']):
                return False
        if not self.wildcards & FlowWildCards.OFPFW_DL_VLAN:
            if 'vlan_vid' not in args:
                return False
            if self.vlan_vid != int(args['vlan_vid']):
                return False
        if not self.wildcards & FlowWildCards.OFPFW_DL_SRC:
            if 'eth_src' not in args:
                return False
            if self.eth_src != args['eth_src']:
                return False
        if not self.wildcards & FlowWildCards.OFPFW_DL_DST:
            if 'eth_dst' not in args:
                return False
            if self.eth_dst != args['eth_dst']:
                return False
        if not self.wildcards & FlowWildCards.OFPFW_DL_TYPE:
            if 'eth_type' not in args:
                return False
            if self.eth_type != int(args['eth_type']):
                return False
        if self.eth_type == constants.IPv4:
            flow_ip_int = int(ipaddress.IPv4Address(self.ipv4_src))
            if flow_ip_int != 0:
                mask = (self.wildcards & FlowWildCards.OFPFW_NW_SRC_MASK) >> \
                       FlowWildCards.OFPFW_NW_SRC_SHIFT
                if mask > 32:
                    mask = 32
                if mask != 32 and 'ipv4_src' not in args:
                    return False
                mask = (0xffffffff << mask) & 0xffffffff
                ip_int = int(ipaddress.IPv4Address(args['ipv4_src']))
                if ip_int & mask != flow_ip_int & mask:
                    return False

            flow_ip_int = int(ipaddress.IPv4Address(self.ipv4_dst))
            if flow_ip_int != 0:
                mask = (self.wildcards & FlowWildCards.OFPFW_NW_DST_MASK) >> \
                       FlowWildCards.OFPFW_NW_DST_SHIFT
                if mask > 32:
                    mask = 32
                if mask != 32 and 'ipv4_dst' not in args:
                    return False
                mask = (0xffffffff << mask) & 0xffffffff
                ip_int = int(ipaddress.IPv4Address(args['ipv4_dst']))
                if ip_int & mask != flow_ip_int & mask:
                    return False
            if not self.wildcards & FlowWildCards.OFPFW_NW_TOS:
                if 'ip_tos' not in args:
                    return False
                if self.ip_tos != int(args['ip_tos']):
                    return False
            if not self.wildcards & FlowWildCards.OFPFW_NW_PROTO:
                if 'ip_proto' not in args:
                    return False
                if self.ip_proto != int(args['ip_proto']):
                    return False
            if not self.wildcards & FlowWildCards.OFPFW_TP_SRC:
                if 'tp_src' not in args:
                    return False
                if self.tcp_src != int(args['tp_src']):
                    return False
            if not self.wildcards & FlowWildCards.OFPFW_TP_DST:
                if 'tp_dst' not in args:
                    return False
                if self.tcp_dst != int(args['tp_dst']):
                    return False

        # for action in self.actions:
        #     if action.action_type == ActionType.OFPAT_OUTPUT:
        #         return '%s' % action.port.value
        return self.to_dict()

    def match13(self, args):
        pass


class Main(KytosNApp):
    """Main class of amlight/kytos_flow_manager NApp.

    This class is the entry point for this napp.
    """

    def setup(self):
        """Replace the '__init__' method for the KytosNApp subclass.

        The setup method is automatically called by the controller when your
        application is loaded.

        So, if you have any setup routine, insert it here.
        """
        log.info('Starting Kytos/Amlight flow manager')
        Switch.match_flows = self.match_flows
        Switch.match_and_apply = self.match_and_apply
        for dpid, switch in self.controller.switches.items():
            switch.generic_flows = []

    def execute(self):
        """This method is executed right after the setup method execution.

        You can also use this method in loop mode if you add to the above setup
        method a line like the following example:

            self.execute_as_loop(30)  # 30-second interval.
        """
        pass

    def shutdown(self):
        """This method is executed when your napp is unloaded.

        If you have some cleanup procedure, insert it here.
        """
        pass

    def flow_from_id(self, flow_id):
        for _, switch in self.controller.switches.items():
            for flow in switch.generic_flows:
                if flow.id == flow_id:
                    return flow
        return None

    @rest('flow/match/<dpid>')
    def flow_match(self, dpid):
        switch = self.controller.get_switch_by_dpid(dpid)
        return jsonify(switch.match_flows(request.args, False))

    @rest('flow/stats/<dpid>')
    def flow_stats(self, dpid):
        switch = self.controller.get_switch_by_dpid(dpid)
        return jsonify(switch.match_flows(request.args, True))

    @staticmethod
    def match_flows(self, args, many=True):
        """
        Tries to match the packet in request against the flows installed in 
        switch with given dpid.
        Tries the match with each flow, in other. If many is True, tries the 
        match with all flows, if False, tries until the first match.
        :param dpid: DPID of the switch
        :param many: Boolean, indicating whether to continue after matching the 
                first flow or not
        :return: If many, the list of matched flows, or the matched flow
        """

        response = []
        for flow in self.generic_flows:
            m = flow.match(args)
            if m:
                if many:
                    response.append(m)
                else:
                    response = m
                    break
        if not many and response == []:
            return None
        return response

    @staticmethod
    def match_and_apply(self, args):
        flow = self.match_flows(args, False)
        port = None
        actions = None
        if flow:
            actions = flow['actions']
            if self.ofp_version == '0x01':
                for action in actions:
                    action_type = int(action['action_type'])
                    if action_type == ActionType.OFPAT_OUTPUT:
                        port = int(action['port'])
                    elif action_type == ActionType.OFPAT_SET_VLAN_VID:
                        args['vlan_vid'] = int(action['vlan_id'])
                    elif action_type == ActionType.OFPAT_SET_VLAN_PCP:
                        args['vlan_pcp'] = int(action['vlan_pcp'])
                    elif action_type == ActionType.OFPAT_STRIP_VLAN:
                        pass  # TODO: strip vlan
                    elif action_type == ActionType.OFPAT_SET_DL_SRC:
                        args['eth_src'] = int(action['dl_src'])
                    elif action_type == ActionType.OFPAT_SET_DL_DST:
                        args['eth_dst'] = int(action['dl_dst'])
                    elif action_type == ActionType.OFPAT_SET_NW_SRC:
                        args['ip4_src'] = int(action['nw_src'])
                    elif action_type == ActionType.OFPAT_SET_NW_DST:
                        args['ip4_dst'] = int(action['nw_dst'])
                    elif action_type == ActionType.OFPAT_SET_NW_TOS:
                        args['ip_tos'] = int(action['nw_tos'])
                    elif action_type == ActionType.OFPAT_SET_TP_SRC:
                        args['tp_src'] = int(action['tp_src'])
                    elif action_type == ActionType.OFPAT_SET_TP_DST:
                        args['tp_dst'] = int(action['tp_dst'])
                    elif action_type == ActionType.OFPAT_ENQUEUE:
                        pass  # TODO: enqueue
        return flow, args, port

    @rest('packet_count/<flow_id>')
    def packet_count(self, flow_id):
        flow = self.flow_from_id(flow_id)
        if flow is None:
            return "Flow does not exist", 404
        else:
            packet_stats = {'flow_id': flow_id,
                            'packet_counter': flow.packet_count,
                            'packet_per_second':
                                flow.packet_count / flow.duration_sec
                           }
            return jsonify(packet_stats)

    @rest('bytes_count/<flow_id>')
    def bytes_count(self, flow_id):
        flow = self.flow_from_id(flow_id)
        if flow is None:
            return "Flow does not exist", 404
        else:
            bytes_stats = {'flow_id': flow_id,
                           'bytes_counter': flow.byte_count,
                           'bits_per_second':
                               flow.byte_count * 8 / flow.duration_sec
                          }
            return jsonify(bytes_stats)

    @rest('packet_count/per_flow/<dpid>')
    def packet_count_per_flow(self, dpid):
        return self.flows_counters('packet_count',
                                   dpid,
                                   counter='packet_counter',
                                   rate='packet_per_second')

    @rest('packet_count/sum/<dpid>')
    def packet_count_sum(self, dpid):
        return self.flows_counters('packet_count',
                                   dpid,
                                   sum=True)

    @rest('bytes_count/per_flow/<dpid>')
    def bytes_count_per_flow(self, dpid):
        return self.flows_counters('byte_count',
                                   dpid,
                                   counter='bytes_counter',
                                   rate='bits_per_second')

    @rest('bytes_count/sum/<dpid>')
    def bytes_count_sum(self, dpid):
        return self.flows_counters('byte_count',
                                   dpid,
                                   sum=True)

    def flows_counters(self, field, dpid, counter=None, rate=None, total=False):
        start_date = request.args.get('start_date', 0)
        end_date = request.args.get('end_date', 0)

        if total:
            count_flows = 0
        else:
            count_flows = []
            if not counter:
                counter = field
            if not rate:
                rate = field

        # We don't have statistics persistence yet, so for now this only works
        # for start and end equals to zero
        flows = self.controller.get_switch_by_dpid(dpid).generic_flows

        for flow in flows:
            count = getattr(flow, field)
            if sum:
                count_flows += count
            else:
                per_second = count / flow.duration_sec
                if rate.startswith('bits'):
                    per_second *= 8
                count_flows.append({'flow_id': flow.id,
                                    counter: count,
                                    rate: per_second})

        return jsonify(count_flows)

    @staticmethod
    @listen_to('kytos/of_core.v0x01.messages.in.ofpt_stats_reply')
    def handle_features_reply(event):
        msg = event.content['message']
        if msg.body_type == common01.StatsTypes.OFPST_FLOW:
            switch = event.source.switch
            switch.generic_flows = []
            for flow_stats in msg.body:
                flow = GenericFlow.from_flow_stats(flow_stats)
                switch.generic_flows.append(flow)
            switch.generic_flows.sort(
                key=lambda f: (f.priority, f.duration_sec),
                reverse=True
            )
