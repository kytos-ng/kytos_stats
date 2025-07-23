"""Main module of amlight/kytos_stats Kytos Network Application.

This NApp does operations with flows not covered by Kytos itself.
"""
# pylint: disable=too-many-return-statements,too-many-instance-attributes
# pylint: disable=too-many-arguments,too-many-branches,too-many-statements

from collections import defaultdict

from kytos.core import KytosNApp, log, rest
from kytos.core.events import KytosEvent
from kytos.core.helpers import alisten_to, listen_to
from kytos.core.rest_api import HTTPException, JSONResponse, Request


# pylint: disable=too-many-public-methods
class Main(KytosNApp):
    """Main class of amlight/kytos_stats NApp.
    This class is the entry point for this napp.
    """

    def setup(self):
        """Replace the '__init__' method for the KytosNApp subclass.
        The setup method is automatically called by the controller when your
        application is loaded.
        So, if you have any setup routine, insert it here.
        """
        log.info('Starting Kytos/Amlight flow manager')
        self.flows_stats_dict = {}
        self.tables_stats_dict = {}
        # port stats data by dpid by port_no
        self.port_stats_dict: dict[str, dict[int, dict]] = defaultdict(dict)

    def execute(self):
        """This method is executed right after the setup method execution.
        You can also use this method in loop mode if you add to the above setup
        method a line like the following example:
            self.execute_as_loop(30)  # 30-second interval.
        """

    def shutdown(self):
        """This method is executed when your napp is unloaded.
        If you have some cleanup procedure, insert it here.
        """

    def flow_from_id(self, flow_id):
        """Flow from given flow_id."""
        return self.flows_stats_dict.get(flow_id)

    def flow_stats_by_dpid_flow_id(self, dpids):
        """ Auxiliar funcion for v1/flow/stats endpoint implementation.
        """
        flow_stats_by_id = {}
        flows_stats_dict_copy = self.flows_stats_dict.copy()
        for flow_id, flow in flows_stats_dict_copy.items():
            dpid = flow.switch.dpid
            if dpid in dpids:
                if dpid not in flow_stats_by_id:
                    flow_stats_by_id[dpid] = {}
                info_flow_as_dict = flow.stats.as_dict()
                info_flow_as_dict.update({"cookie": flow.cookie})
                info_flow_as_dict.update({"priority": flow.priority})
                info_flow_as_dict.update({"match": flow.match.as_dict()})
                flow_stats_by_id[dpid].update({flow_id: info_flow_as_dict})
        return flow_stats_by_id

    def table_stats_by_dpid_table_id(self, dpids, table_ids):
        """ Auxiliar funcion for v1/table/stats endpoint implementation.
        """
        table_stats_by_id = {}
        tables_stats_dict_copy = self.tables_stats_dict.copy()
        for dpid, tables in tables_stats_dict_copy.items():
            if dpid not in dpids:
                continue
            table_stats_by_id[dpid] = {}
            if len(table_ids) == 0:
                table_ids = list(tables.keys())
            for table_id, table in tables.items():
                if table_id in table_ids:
                    table_dict = table.as_dict()
                    del table_dict['switch']
                    table_stats_by_id[dpid][table_id] = table_dict
        return table_stats_by_id

    def port_stats_filter(
        self, f_dpids: list[str], f_ports: list[int]
    ) -> dict:
        """ Auxiliar funcion for v1/port/stats endpoint implementation.
        """
        port_stats = {}
        dpid_keys = (
            (dpid for dpid in f_dpids if dpid in self.port_stats_dict)
            if f_dpids
            else self.port_stats_dict.keys()
        )
        for dpid in dpid_keys:
            port_stats[dpid] = {}
            port_keys = f_ports
            if not f_ports:
                port_keys = self.port_stats_dict[dpid].keys()
            for port_no in port_keys:
                if p_stat := self.port_stats_dict[dpid].get(port_no):
                    port_stats[dpid][port_no] = p_stat
        return port_stats

    @rest('v1/flow/stats')
    def flow_stats(self, request: Request) -> JSONResponse:
        """Return the flows stats by dpid.
        Return the stats of all flows if dpid is None
        """
        dpids = request.query_params.getlist("dpid")
        if len(dpids) == 0:
            dpids = [sw.dpid for sw in self.controller.switches.values()]
        flow_stats_by_id = self.flow_stats_by_dpid_flow_id(dpids)
        return JSONResponse(flow_stats_by_id)

    @rest('v1/table/stats')
    def table_stats(self, request: Request) -> JSONResponse:
        """Return the table stats by dpid,
        and optionally by table_id.
        """
        dpids = request.query_params.getlist("dpid")
        if len(dpids) == 0:
            dpids = [sw.dpid for sw in self.controller.switches.values()]
        table_ids = request.query_params.getlist("table")
        table_ids = list(map(int, table_ids))
        table_stats_dpid = self.table_stats_by_dpid_table_id(dpids, table_ids)
        return JSONResponse(table_stats_dpid)

    @rest('v1/port/stats')
    async def port_stats(self, request: Request) -> JSONResponse:
        """Return the port stats by dpid, and optionally by port."""
        dpids = request.query_params.getlist("dpid")
        try:
            ports = list(map(int, request.query_params.getlist("port")))
        except (ValueError, TypeError):
            detail = "'port' value is supposed to be an integer"
            raise HTTPException(400, detail=detail)
        return JSONResponse(self.port_stats_filter(dpids, ports))

    @rest('v1/packet_count/{flow_id}')
    def packet_count(self, request: Request) -> JSONResponse:
        """Packet count of an specific flow."""
        flow_id = request.path_params["flow_id"]
        flow = self.flow_from_id(flow_id)
        if flow is None:
            raise HTTPException(404, detail="Flow does not exist")
        try:
            packet_per_second = \
                flow.stats.packet_count / flow.stats.duration_sec
        except ZeroDivisionError:
            packet_per_second = 0
        packet_stats = {
            'flow_id': flow_id,
            'packet_counter': flow.stats.packet_count,
            'packet_per_second': packet_per_second
            }
        return JSONResponse(packet_stats)

    @rest('v1/bytes_count/{flow_id}')
    def bytes_count(self, request: Request) -> JSONResponse:
        """Bytes count of an specific flow."""
        flow_id = request.path_params["flow_id"]
        flow = self.flow_from_id(flow_id)
        if flow is None:
            raise HTTPException(404, detail="Flow does not exist")
        try:
            bits_per_second = \
                flow.stats.byte_count * 8 / flow.stats.duration_sec
        except ZeroDivisionError:
            bits_per_second = 0
        bytes_stats = {
            'flow_id': flow_id,
            'bytes_counter': flow.stats.byte_count,
            'bits_per_second': bits_per_second
            }
        return JSONResponse(bytes_stats)

    @rest('v1/packet_count/per_flow/{dpid}')
    def packet_count_per_flow(self, request: Request) -> JSONResponse:
        """Per flow packet count."""
        dpid = request.path_params["dpid"]
        return self.flows_counters('packet_count',
                                   dpid,
                                   counter='packet_counter',
                                   rate='packet_per_second')

    @rest('v1/bytes_count/per_flow/{dpid}')
    def bytes_count_per_flow(self, request: Request) -> JSONResponse:
        """Per flow bytes count."""
        dpid = request.path_params["dpid"]
        return self.flows_counters('byte_count',
                                   dpid,
                                   counter='bytes_counter',
                                   rate='bits_per_second')

    def flows_counters(self, field, dpid, counter=None, rate=None,
                       total=False) -> JSONResponse:
        """Calculate flows statistics.
        The returned statistics are both per flow and for the sum of flows
        """

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
        flows = self.flow_stats_by_dpid_flow_id([dpid])
        flows = flows.get(dpid)

        if flows is None:
            return JSONResponse(count_flows)
        for flow_id, stats in flows.items():
            count = stats[field]
            if total:
                count_flows += count
            else:
                try:
                    per_second = count / stats['duration_sec']
                except ZeroDivisionError:
                    per_second = 0
                if rate.startswith('bits'):
                    per_second *= 8
                count_flows.append({'flow_id': flow_id,
                                    counter: count,
                                    rate: per_second})
        return JSONResponse(count_flows)

    @listen_to('kytos/of_core.flow_stats.received')
    def on_stats_received(self, event):
        """Capture flow stats messages for OpenFlow 1.3."""
        self.handle_stats_received(event)

    def handle_stats_received(self, event):
        """Handle flow stats messages for OpenFlow 1.3."""
        if 'replies_flows' in event.content:
            replies_flows = event.content['replies_flows']
            self.handle_stats_reply_received(replies_flows)

    def handle_stats_reply_received(self, replies_flows):
        """Update the set of flows stats"""
        self.flows_stats_dict.update({flow.id: flow for flow in replies_flows})

    @listen_to('kytos/of_core.table_stats.received')
    def on_table_stats_received(self, event):
        """Capture table stats messages for OpenFlow 1.3."""
        self.handle_table_stats_received(event)

    def handle_table_stats_received(self, event):
        """Handle table stats messages for OpenFlow 1.3."""
        replies_tables = event.content['replies_tables']
        self.handle_table_stats_reply_received(replies_tables)

    def handle_table_stats_reply_received(self, replies_tables):
        """Update the set of tables stats"""
        for table in replies_tables:
            switch_id = table.switch.id
            if switch_id not in self.tables_stats_dict:
                self.tables_stats_dict[switch_id] = {}
            self.tables_stats_dict[switch_id][table.table_id] = table

    @alisten_to('kytos/of_core.port_stats')
    async def on_port_stats(self, event: KytosEvent) -> None:
        """Handle port stats messages for OpenFlow 1.3."""
        port_stats = event.content.get('port_stats')
        switch = event.content.get('switch')
        if not port_stats or not switch:
            return
        for port in port_stats:
            self.port_stats_dict[switch.id][port.port_no.value] = {
                "port_no": port.port_no.value,
                "rx_packets": port.rx_packets.value,
                "tx_packets": port.tx_packets.value,
                "rx_bytes": port.rx_bytes.value,
                "tx_bytes": port.tx_bytes.value,
                "rx_dropped": port.rx_dropped.value,
                "tx_dropped": port.tx_dropped.value,
                "rx_errors": port.rx_errors.value,
                "tx_errors": port.tx_errors.value,
                "rx_frame_err": port.rx_frame_err.value,
                "rx_over_err": port.rx_over_err.value,
                "rx_crc_err": port.rx_crc_err.value,
                "collisions": port.collisions.value,
                "duration_sec": port.duration_sec.value,
                "duration_nsec": port.duration_nsec.value,
            }
