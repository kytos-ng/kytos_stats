from kytos.core import log
from napps.amlight.sdntrace.shared.singleton import Singleton
from pyof.v0x01.common.action import ActionType, ActionOutput, ActionStripVlan, ActionEnqueue, ActionVlanVid, ActionVlanPCP, ActionDLAddr, ActionNWAddr, ActionNWTos, ActionTPPort, ActionVendorHeader

ACTION_TYPES = {
    ActionType.OFPAT_OUTPUT: ActionOutput,
    ActionType.OFPAT_SET_VLAN_VID: ActionVlanVid,
    ActionType.OFPAT_SET_VLAN_PCP: ActionVlanPCP,
    ActionType.OFPAT_STRIP_VLAN: ActionStripVlan,
    ActionType.OFPAT_SET_DL_SRC: ActionDLAddr,
    ActionType.OFPAT_SET_DL_DST: ActionDLAddr,
    ActionType.OFPAT_SET_NW_SRC: ActionNWAddr,
    ActionType.OFPAT_SET_NW_DST: ActionNWAddr,
    ActionType.OFPAT_SET_NW_TOS: ActionNWTos,
    ActionType.OFPAT_SET_TP_SRC: ActionTPPort,
    ActionType.OFPAT_SET_TP_DST: ActionTPPort,
    ActionType.OFPAT_ENQUEUE: ActionEnqueue,
}

class Flows(metaclass=Singleton):
    """Class to store all flows installed in the switches
    """
    def __init__(self):
        self._flows = dict()

    def clear(self, dpid):
        self._flows[dpid] = list()

    def add_flow(self, dpid, flow):
        if dpid not in self._flows:
            self._flows[dpid] = list()
        self._flows[dpid].append(flow)

    def get_flows(self, dpid):
        if dpid in self._flows:
            return self._flows[dpid]

    def sort(self, dpid):
        if dpid in self._flows:
            self._flows[dpid].sort(key=lambda f: f.priority, reverse=True)

