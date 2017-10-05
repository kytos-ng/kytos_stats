REST definition:

GET /flows/packet_count/<dpid>?start_date=0&end_date=0
GET /flows/byte_count/<dpid>?start_date=0&end_date=0

Returns flow packet(byte) count for all flows of a switch from start date to end date.
The count is given in total packets(bytes) and in packets(bytes) per second. If start date is zero or prior to flow installation, counts since flow installation. If end date is zero, counts until present date or until flow removal.

For now, as there is no persistence, ignores start and end dates.