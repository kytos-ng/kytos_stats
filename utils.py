from napps.amlight.sdntrace.shared.singleton import Singleton


class Flows(metaclass=Singleton):
    """Class to store all flows installed in the switches."""

    def __init__(self):
        """Institate an empty flow dict."""
        self._flows = dict()

    def clear(self, dpid):
        """Clear the list of flows of the given switch."""
        self._flows[dpid] = list()

    def add_flow(self, dpid, flow):
        """Add a flow to the list of flows of the given switch."""
        if dpid not in self._flows:
            self._flows[dpid] = list()
        self._flows[dpid].append(flow)

    def get_flows(self, dpid):
        """Return the list of flows of the given switch."""
        if dpid in self._flows:
            return self._flows[dpid]
        return None

    def sort(self, dpid):
        """Sort the list of flows of the given switch by priority."""
        if dpid in self._flows:
            self._flows[dpid].sort(key=lambda f: f.priority, reverse=True)

