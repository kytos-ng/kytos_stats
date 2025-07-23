"""Module to test the main napp file."""
from unittest.mock import MagicMock, patch
from kytos.lib.helpers import (
    get_controller_mock,
    get_test_client,
    get_kytos_event_mock,
    get_switch_mock,
)
from napps.amlight.kytos_stats.main import Main


# pylint: disable=too-many-public-methods, too-many-lines
class TestMain:
    """Test the Main class."""

    def setup_method(self):
        """Execute steps before each tests."""
        controller = get_controller_mock()
        self.napp = Main(controller)
        self.api_client = get_test_client(controller, self.napp)
        self.base_endpoint = "amlight/kytos_stats/v1"

    def test_get_event_listeners(self):
        """Verify all event listeners registered."""
        expected_events = [
            'kytos/of_core.flow_stats.received',
            'kytos/of_core.table_stats.received',
            'kytos/of_core.port_stats',
        ]
        actual_events = self.napp.listeners()

        for _event in expected_events:
            assert _event in actual_events

    def test_execute(self):
        """Test execute."""

    def test_shutdown(self):
        """Test shutdown."""

    def test_flow_from_id(self):
        """Test flow_from_id function"""
        flow = self._get_mocked_flow_base()
        self.napp.flows_stats_dict = {
            flow.id: flow
        }
        results = self.napp.flow_from_id(flow.id)
        assert results.id == flow.id

    def test_flow_from_id__fail(self):
        """Test flow_from_id function"""
        flow = self._get_mocked_flow_base()
        self.napp.flows_stats_dict = {
            flow.id: flow
        }
        results = self.napp.flow_from_id('1')
        assert results is None

    def test_flow_from_id__empty(self):
        """Test flow_from_id function when flows_stats_dict is empty"""
        self.napp.flows_stats_dict = {}
        results = self.napp.flow_from_id('1')
        assert results is None

    async def test_packet_count_not_found(self):
        """Test packet_count rest call with wrong flow_id."""
        flow_id = "123456789"
        endpoint = f"{self.base_endpoint}/packet_count/{flow_id}"
        response = await self.api_client.get(endpoint)
        assert response.status_code == 404
        assert response.json()["description"] == "Flow does not exist"

    @patch("napps.amlight.kytos_stats.main.Main.flow_from_id")
    async def test_packet_count(self, mock_from_flow):
        """Test packet_count rest call."""
        flow_id = '1'
        mock_from_flow.return_value = self._get_mocked_flow_base()

        self._patch_switch_flow(flow_id)
        endpoint = f"{self.base_endpoint}/packet_count/{flow_id}"
        response = await self.api_client.get(endpoint)
        assert response.status_code == 200
        json_response = response.json()
        assert json_response["flow_id"] == flow_id
        assert json_response["packet_counter"] == 40
        assert json_response["packet_per_second"] == 2.0

    async def test_bytes_count_not_found(self):
        """Test bytes_count rest call with wrong flow_id."""
        flow_id = "123456789"
        endpoint = f"{self.base_endpoint}/bytes_count/{flow_id}"
        response = await self.api_client.get(endpoint)
        assert response.status_code == 404
        assert response.json()["description"] == "Flow does not exist"

    @patch("napps.amlight.kytos_stats.main.Main.flow_from_id")
    async def test_bytes_count(self, mock_from_flow):
        """Test bytes_count rest call."""
        flow_id = '1'
        mock_from_flow.return_value = self._get_mocked_flow_base()
        self._patch_switch_flow(flow_id)

        endpoint = f"{self.base_endpoint}/bytes_count/{flow_id}"
        response = await self.api_client.get(endpoint)
        assert response.status_code == 200
        json_response = response.json()
        assert json_response["flow_id"] == flow_id
        assert json_response["bytes_counter"] == 10
        assert json_response["bits_per_second"] == 4.0

    async def test_packet_count_per_flow_empty(self):
        """Test packet_count rest call with a flow that does not exist ."""
        flow_id = "123456789"
        endpoint = f"{self.base_endpoint}/packet_count/per_flow/{flow_id}"
        response = await self.api_client.get(endpoint)
        assert response.status_code == 200
        assert len(response.json()) == 0

    @patch("napps.amlight.kytos_stats.main.Main.flow_stats_by_dpid_flow_id")
    async def test_packet_count_per_flow(self, mock_from_flow):
        """Test packet_count_per_flow rest call."""
        flow_info = {
            "byte_count": 10,
            "duration_sec": 20,
            "duration_nsec": 30,
            "packet_count": 40,
            "cookie": 12310228866111668291,
            "match": {"in_port": 1},
            "priority": 32768
            }
        flow_id = '6055f13593fad45e0b4699f49d56b105'
        flow_stats_dict_mock = {flow_id: flow_info}
        dpid = "00:00:00:00:00:00:00:01"
        flow_by_sw = {dpid: flow_stats_dict_mock}
        mock_from_flow.return_value = flow_by_sw

        self._patch_switch_flow(flow_id)
        endpoint = f"{self.base_endpoint}/packet_count/per_flow/{dpid}"
        response = await self.api_client.get(endpoint)

        json_response = response.json()
        assert json_response[0]["flow_id"] == flow_id
        assert json_response[0]["packet_counter"] == 40
        assert json_response[0]["packet_per_second"] == 2.0

    async def test_bytes_count_per_flow__empty(self):
        """Test bytes_count rest call with a flow that does not exist ."""
        flow_id = "123456789"
        endpoint = f"{self.base_endpoint}/bytes_count/per_flow/{flow_id}"
        response = await self.api_client.get(endpoint)
        assert response.status_code == 200
        assert len(response.json()) == 0

    @patch("napps.amlight.kytos_stats.main.Main.flow_stats_by_dpid_flow_id")
    async def test_bytes_count_per_flow(self, mock_from_flow):
        """Test bytes_count_per_flow rest call."""
        flow_info = {
            "byte_count": 10,
            "duration_sec": 20,
            "duration_nsec": 30,
            "packet_count": 40,
            "cookie": 12310228866111668291,
            "match": {"in_port": 1},
            "priority": 32768
            }
        flow_id = '6055f13593fad45e0b4699f49d56b105'
        flow_stats_dict_mock = {flow_id: flow_info}
        dpid = "00:00:00:00:00:00:00:01"
        flow_by_sw = {dpid: flow_stats_dict_mock}
        mock_from_flow.return_value = flow_by_sw

        self._patch_switch_flow(flow_id)

        endpoint = f"{self.base_endpoint}/bytes_count/per_flow/{dpid}"
        response = await self.api_client.get(endpoint)
        assert response.status_code == 200

        json_response = response.json()
        assert json_response[0]["flow_id"] == flow_id
        assert json_response[0]["bytes_counter"] == 10
        assert json_response[0]["bits_per_second"] == 4.0

    @patch("napps.amlight.kytos_stats.main.Main.flow_stats_by_dpid_flow_id")
    async def test_flows_counters_packet(self, mock_from_flow):
        """Test flows_counters function for packet"""
        flow_info = {
            "byte_count": 10,
            "duration_sec": 20,
            "duration_nsec": 30,
            "packet_count": 40,
            "cookie": 12310228866111668291,
            "match": {"in_port": 1},
            "priority": 32768
            }
        flow_id = '6055f13593fad45e0b4699f49d56b105'
        flow_stats_dict_mock = {flow_id: flow_info}
        dpid = "00:00:00:00:00:00:00:01"
        flow_by_sw = {dpid: flow_stats_dict_mock}
        mock_from_flow.return_value = flow_by_sw

        endpoint = f"{self.base_endpoint}/packet_count/per_flow/{dpid}"
        response = await self.api_client.get(endpoint)
        assert response.status_code == 200
        assert len(response.json()) == 1

    @patch("napps.amlight.kytos_stats.main.Main.flow_stats_by_dpid_flow_id")
    async def test_flows_counters_bytes(self, mock_from_flow):
        """Test flows_counters function for bytes"""
        flow_info = {
            "byte_count": 10,
            "duration_sec": 20,
            "duration_nsec": 30,
            "packet_count": 40,
            "cookie": 12310228866111668291,
            "match": {"in_port": 1},
            "priority": 32768
            }
        flow_id = '6055f13593fad45e0b4699f49d56b105'
        flow_stats_dict_mock = {flow_id: flow_info}
        dpid = "00:00:00:00:00:00:00:01"
        flow_by_sw = {dpid: flow_stats_dict_mock}
        mock_from_flow.return_value = flow_by_sw

        endpoint = f"{self.base_endpoint}/bytes_count/per_flow/{dpid}"
        response = await self.api_client.get(endpoint)
        assert response.status_code == 200
        assert len(response.json()) == 1

    @patch("napps.amlight.kytos_stats.main.Main.flow_stats_by_dpid_flow_id")
    async def test_flow_stats_by_dpid_flow_id(self, mock_from_flow):
        """Test flow_stats rest call."""
        flow_info = {
            "byte_count": 10,
            "duration_sec": 20,
            "duration_nsec": 30,
            "packet_count": 40,
            "cookie": 12310228866111668291,
            "match": {"in_port": 1},
            "priority": 32768
            }
        flow_stats_dict_mock = {'6055f13593fad45e0b4699f49d56b105': flow_info}
        flow_by_sw = {"00:00:00:00:00:00:00:01": flow_stats_dict_mock}
        mock_from_flow.return_value = flow_by_sw

        endpoint = "/flow/stats?dpid=00:00:00:00:00:00:00:01"
        url = f"{self.base_endpoint}{endpoint}"
        response = await self.api_client.get(url)
        assert response.status_code == 200
        expected = flow_by_sw
        assert response.json() == expected

    @patch("napps.amlight.kytos_stats.main.Main.flow_stats_by_dpid_flow_id")
    async def test_flow_stats_by_dpid_flow_id_without_dpid(self,
                                                           mock_from_flow):
        """Test flow_stats rest call."""
        flow_info = {
            "byte_count": 10,
            "duration_sec": 20,
            "duration_nsec": 30,
            "packet_count": 40,
            "cookie": 12310228866111668291,
            "match": {"in_port": 1},
            "priority": 32768
            }
        flow_stats_dict_mock = {'6055f13593fad45e0b4699f49d56b105': flow_info}
        flow_by_sw = {"00:00:00:00:00:00:00:01": flow_stats_dict_mock}
        mock_from_flow.return_value = flow_by_sw

        endpoint = "/flow/stats"
        url = f"{self.base_endpoint}{endpoint}"
        response = await self.api_client.get(url)
        assert response.status_code == 200

        expected = flow_by_sw
        assert response.json() == expected

    @patch("napps.amlight.kytos_stats.main.Main.flow_stats_by_dpid_flow_id")
    async def test_flow_stats_by_dpid_flow_id_with_dpid(self, mock_from_flow):
        """Test flow_stats rest call."""
        flow_info = {
            "byte_count": 10,
            "duration_sec": 20,
            "duration_nsec": 30,
            "packet_count": 40,
            "cookie": 12310228866111668291,
            "match": {"in_port": 1},
            "priority": 32768
            }
        flow_stats_dict_mock = {'6055f13593fad45e0b4699f49d56b105': flow_info}
        flow_by_sw = {"00:00:00:00:00:00:00:01": flow_stats_dict_mock}
        mock_from_flow.return_value = flow_by_sw

        endpoint = "/flow/stats?dpid=00:00:00:00:00:00:00:01"
        url = f"{self.base_endpoint}{endpoint}"
        response = await self.api_client.get(url)
        assert response.status_code == 200

        expected = flow_by_sw
        assert response.json() == expected

    @patch("napps.amlight.kytos_stats.main.Main.flow_stats_by_dpid_flow_id")
    async def test_flow_stats_by_dpid_flow_id_not_found(self, mock_from_flow):
        """Test flow_stats rest call."""
        flow_by_sw = {}
        mock_from_flow.return_value = flow_by_sw
        endpoint = "/flow/stats?dpid=00:00:00:00:00:00:00:01"
        url = f"{self.base_endpoint}{endpoint}"
        response = await self.api_client.get(url)
        assert response.status_code == 200
        assert len(response.json()) == 0

    @patch("napps.amlight.kytos_stats.main.Main.table_stats_by_dpid_table_id")
    async def test_table_stats_by_dpid_table_id(self, mock_from_table):
        """Test table_stats rest call."""
        table_info = {
            "table_id": 10,
            "active_count": 20,
            "lookup_count": 30,
            "matched_count": 32768
            }
        table_stats_dict_mock = {'10': table_info}
        table_by_sw = {"00:00:00:00:00:00:00:01": table_stats_dict_mock}
        mock_from_table.return_value = table_by_sw

        endpoint = "/table/stats?dpid=00:00:00:00:00:00:00:01&table=10"
        url = f"{self.base_endpoint}{endpoint}"
        response = await self.api_client.get(url)
        assert response.status_code == 200
        expected = table_by_sw
        assert response.json() == expected

    async def test_port_stats_filter(self):
        """Test table_stats rest call."""
        self.napp.port_stats_dict = {
            "0x1": {
                1: {
                    "port_no": 1,
                },
                2: {
                    "port_no": 2,
                },
            },
            "0x2": {
                99: {
                    "port_no": 99,
                },
            },
        }
        expected_result = {}
        for dpid, sw in self.napp.port_stats_dict.items():
            expected_result[dpid] = {}
            for port_no, port in sw.items():
                expected_result[dpid][str(port_no)] = port

        endpoint = "/port/stats"
        url = f"{self.base_endpoint}{endpoint}"
        response = await self.api_client.get(url)
        assert response.status_code == 200
        assert response.json() == expected_result

        endpoint = "/port/stats?dpid=0x1&port=1"
        url = f"{self.base_endpoint}{endpoint}"
        response = await self.api_client.get(url)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert "0x1" in data
        assert len(data["0x1"]) == 1
        assert "1" in data["0x1"]

    async def test_on_port_stats(self):
        """Test handle_stats_received function."""
        expected_dict = {
            "00:00:00:00:00:00:00:01": {
                1: {
                    "port_no": 1,
                    "rx_packets": 0,
                    "tx_packets": 0,
                    "rx_bytes": 0,
                    "tx_bytes": 0,
                    "rx_dropped": 0,
                    "tx_dropped": 0,
                    "rx_errors": 0,
                    "tx_errors": 0,
                    "rx_frame_err": 0,
                    "rx_over_err": 0,
                    "rx_crc_err": 0,
                    "collisions": 0,
                    "duration_sec": 0,
                    "duration_nsec": 0,
                },
            },
        }

        name = "kytos/of_core.port_stats"
        event = get_kytos_event_mock(name=name, content={})

        await self.napp.on_port_stats(event)

        assert not self.napp.port_stats_dict

        switch = get_switch_mock("00:00:00:00:00:00:00:01", 0x04)
        switch.id = switch.dpid
        port_stats = self._get_mocked_port_stat(port_no=1)
        content = {"switch": switch, "port_stats": [port_stats]}

        event = get_kytos_event_mock(name=name, content=content)

        await self.napp.on_port_stats(event)

        assert self.napp.port_stats_dict == expected_dict

    @patch("napps.amlight.kytos_stats.main.Main.table_stats_by_dpid_table_id")
    async def test_table_stats_by_dpid_table_id_without_dpid(self,
                                                             mock_from_table):
        """Test table_stats rest call."""
        table_info = {
            "table_id": 10,
            "active_count": 20,
            "lookup_count": 30,
            "matched_count": 32768
            }
        table_stats_dict_mock = {'10': table_info}
        table_by_sw = {"00:00:00:00:00:00:00:01": table_stats_dict_mock}
        mock_from_table.return_value = table_by_sw

        endpoint = "/table/stats"
        url = f"{self.base_endpoint}{endpoint}"
        response = await self.api_client.get(url)
        assert response.status_code == 200

        expected = table_by_sw
        assert response.json() == expected

    @patch("napps.amlight.kytos_stats.main.Main.table_stats_by_dpid_table_id")
    async def test_table_stats_by_dpid_table_id_not_found(self,
                                                          mock_from_table):
        """Test table_stats rest call."""
        table_by_sw = {}
        mock_from_table.return_value = table_by_sw
        endpoint = "/flow/stats?dpid=00:00:00:00:00:00:00:01"
        url = f"{self.base_endpoint}{endpoint}"
        response = await self.api_client.get(url)
        assert response.status_code == 200
        assert len(response.json()) == 0

    def _patch_switch_flow(self, flow_id):
        """Helper method to patch controller to return switch/flow data."""
        # patching the flow_stats object in the switch
        flow = self._get_mocked_flow_stats()
        flow.id = flow_id
        switch = MagicMock()
        self.napp.controller.switches = {"1": switch}
        self.napp.controller.get_switch_by_dpid = MagicMock()
        self.napp.controller.get_switch_by_dpid.return_value = switch

    def _get_mocked_flow_stats(self):
        """Helper method to create a mock flow_stats object."""
        flow_stats = MagicMock()
        flow_stats.id = 123
        flow_stats.byte_count = 10
        flow_stats.duration_sec = 20
        flow_stats.duration_nsec = 30
        flow_stats.packet_count = 40
        return flow_stats

    def _get_mocked_multipart_replies_flows(self):
        """Helper method to create mock multipart replies flows"""
        flow = self._get_mocked_flow_base()

        instruction = MagicMock()
        flow.instructions = [instruction]

        replies_flows = [flow]
        return replies_flows

    def _get_mocked_multipart_replies_tables(self):
        """Helper method to create mock multipart replies tables"""
        table = MagicMock()
        table.table_id = 10
        table.active_count = 0
        table.lookup_count = 0
        table.matched_count = 0

        replies_tables = [table]
        return replies_tables

    def _get_mocked_port_stat(self, **kwargs):
        """Helper method to create mock port stats."""
        port_stats = MagicMock()
        port_stats.port_no.value = kwargs.get("port_no", 0)
        port_stats.rx_packets.value = kwargs.get("rx_packets", 0)
        port_stats.tx_packets.value = kwargs.get("tx_packets", 0)
        port_stats.rx_bytes.value = kwargs.get("rx_bytes", 0)
        port_stats.tx_bytes.value = kwargs.get("tx_bytes", 0)
        port_stats.rx_dropped.value = kwargs.get("rx_dropped", 0)
        port_stats.tx_dropped.value = kwargs.get("tx_dropped", 0)
        port_stats.rx_errors.value = kwargs.get("rx_errors", 0)
        port_stats.tx_errors.value = kwargs.get("tx_errors", 0)
        port_stats.rx_frame_err.value = kwargs.get("rx_frame_err", 0)
        port_stats.rx_over_err.value = kwargs.get("rx_over_err", 0)
        port_stats.rx_crc_err.value = kwargs.get("rx_crc_err", 0)
        port_stats.collisions.value = kwargs.get("collisions", 0)
        port_stats.duration_sec.value = kwargs.get("duration_sec", 0)
        port_stats.duration_nsec.value = kwargs.get("duration_nsec", 0)
        return port_stats

    def _get_mocked_flow_base(self):
        """Helper method to create a mock flow object."""
        flow = MagicMock()
        flow.id = 456
        flow.switch = None
        flow.table_id = None
        flow.match = None
        flow.priority = None
        flow.idle_timeout = None
        flow.hard_timeout = None
        flow.cookie = None
        flow.stats = self._get_mocked_flow_stats()
        return flow

    @patch("napps.amlight.kytos_stats.main.Main.handle_stats_reply_received")
    def test_handle_stats_received(self, mock_handle_stats):
        """Test handle_stats_received function."""

        switch_v0x04 = get_switch_mock("00:00:00:00:00:00:00:01", 0x04)
        replies_flows = self._get_mocked_multipart_replies_flows()
        name = "kytos/of_core.flow_stats.received"
        content = {"switch": switch_v0x04, "replies_flows": replies_flows}

        event = get_kytos_event_mock(name=name, content=content)

        self.napp.handle_stats_received(event)
        mock_handle_stats.assert_called_once()

    @patch("napps.amlight.kytos_stats.main.Main.handle_stats_reply_received")
    def test_handle_stats_received__fail(self, mock_handle_stats):
        """Test handle_stats_received function for
        fail when replies_flows is not in content."""

        switch_v0x04 = get_switch_mock("00:00:00:00:00:00:00:01", 0x04)
        name = "kytos/of_core.flow_stats.received"
        content = {"switch": switch_v0x04}

        event = get_kytos_event_mock(name=name, content=content)

        self.napp.handle_stats_received(event)
        mock_handle_stats.assert_not_called()

    def test_handle_stats_reply_received(self):
        """Test handle_stats_reply_received call."""

        flows_mock = self._get_mocked_multipart_replies_flows()
        self.napp.handle_stats_reply_received(flows_mock)

        assert list(self.napp.flows_stats_dict.values())[0].id == 456

    @patch("napps.amlight.kytos_stats.main.Main.handle_table_stats_received")
    def test_handle_table_stats_received(self, mock_handle_stats):
        """Test handle_table_stats_received function."""

        switch_v0x04 = get_switch_mock("00:00:00:00:00:00:00:01", 0x04)
        replies_tables = self._get_mocked_multipart_replies_tables()
        name = "kytos/of_core.table_stats.received"
        content = {"switch": switch_v0x04, "replies_tables": replies_tables}

        event = get_kytos_event_mock(name=name, content=content)

        self.napp.handle_table_stats_received(event)
        mock_handle_stats.assert_called_once()

    def test_handle_table_stats_reply_received(self):
        """Test handle_table_stats_reply_received call."""

        tables_mock = self._get_mocked_multipart_replies_tables()
        self.napp.handle_table_stats_reply_received(tables_mock)
        table = list(self.napp.tables_stats_dict.values())[0]
        assert list(table.keys())[0] == 10

    @patch("napps.amlight.kytos_stats.main.Main.flow_stats_by_dpid_flow_id")
    async def test_flows_counters_div_zero(self, mock_from_flow):
        """Test that there is no error due to division by zero."""
        flow_info = {
            "byte_count": 10,
            "packet_count": 20,
            "duration_sec": 0
            }
        flow_id = '6055f13593fad45e0b4699f49d56b105'
        flow_stats_dict_mock = {flow_id: flow_info}
        dpid = "00:00:00:00:00:00:00:01"
        flow_by_sw = {dpid: flow_stats_dict_mock}
        mock_from_flow.return_value = flow_by_sw

        self._patch_switch_flow(flow_id)
        endpoint = f"{self.base_endpoint}/packet_count/per_flow/{dpid}"
        response = await self.api_client.get(endpoint)
        response = response.json()
        assert response[0]["flow_id"] == flow_id
        assert response[0]["packet_per_second"] == 0

        endpoint = f"{self.base_endpoint}/bytes_count/per_flow/{dpid}"
        response = await self.api_client.get(endpoint)
        response = response.json()
        assert response[0]["flow_id"] == flow_id
        assert response[0]["bits_per_second"] == 0
