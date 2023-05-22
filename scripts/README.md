## Kytos_stats's scripts

This folder contains Kytos_stats's related scripts.

### Integration Kytos-ng and Zabbix for Monitoring

[`kytos_zabbix.py`](./kytos_zabbix.py) is a script to help on the Kytos-ng monitoring for Zabbix.

#### Pre-requisites

- There's no additional Python libraries dependencies required (the libs we use are usually installed by default).
- Make sure your Kytos server is running and allowing requests on the Napp `kytos_stats`, `mef_eline` and `topology` (via HTTP GET method).
- When using authentication (recommended), you will have three options to provide the credentials: via command line parameters (unsafe) `--user` and `--pass`; via a file in the filesystem (`--passfile`) which contains the username in the first line and the password in the second line (you can change the permissions of the file to restrict access); via environment variables, such as:
- Export  related variables that [kytos_zabbix.py](scripts/kytos_zabbix.py) optionally uses

```
export KYTOS_URL=https://mykytoserver.domain.com/api
export KYTOS_TIMEOUT=5
export KYTOS_USERNAME=zabbix_reader
export KYTOS_PASSWORD=changeme123
```

#### How to use

The `kytos_zabbix.py` script has a few monitoring capabilities, such as the monitoring option `-o`: 1 - status of switches; 2 - status of links; 3 - status of EVCs; 4 - statistics of EVCs. You can filter by the target to be monitored by using the option `-t` (target), example: to get the status of switch01 (dpid 00:00:00:00:00:00:00:01) one would use `-o 1 -t 00:00:00:00:00:00:00:01`. Furthermore, when collecting statistics for EVCs, you can filter by (option `-s`): 1 - bytes/UNI_A, 2 - bytes/UNI_Z , 3 - packets/UNI_A, 4 - packets/UNI_Z.

Here is the complete help and options:

```
# ./kytos_zabbix.py --help
usage: kytos_zabbix.py [-h] [-l URL] [-u USERNAME] [-p PASSWORD] [-f AUTHFILE]
                       [-c CACHE_POLICY] [-o {1,2,3,4,5}] [-t TARGET]
                       [-z {1,2}] [-s {1,2,3,4}]

optional arguments:
  -h, --help            show this help message and exit
  -l URL, --url URL     URL for your Kytos REST API
  -u USERNAME, --user USERNAME
                        Username to authenticate into Kytos API
  -p PASSWORD, --pass PASSWORD
                        Password to authenticate into Kytos API
  -f AUTHFILE, --authfile AUTHFILE
                        Authentication file containing username (first line)
                        and password (second line) to authenticate into Kytos
                        API
  -T TIMEOUT, --timeout TIMEOUT
                        You can tell Requests to stop waiting for a response
                        after a given number of seconds
  -c CACHE_POLICY, --cache_policy CACHE_POLICY
                        Cache policy: never, always or X seconds (default to
                        cache for 600 seconds)
  -o {1,2,3,4,5,6}, --monitoring_option {1,2,3,4,5,6}
                        Monitoring option: 1 - for monitor nodes, 2 - for
                        monitor links, 3 - for monitor evcs (status), 4 - evc
                        statistics, 5 - OpenFlow flows stats, 6 - OpenFlow tables stats
  -t TARGET, --target TARGET
                        Item status (0-down/others, 1-disabled, 2-up/primary,
                        3-up/backup). Argument is the item id to be monitored
                        (depending on the -o option).
  -z {1,2}, --zabbix_output {1,2}
                        Zabbix LLD: (1) Count number of lines in each output
                        or (2) list-only registers
  -s {1,2,3,4}, --stats {1,2,3,4}
                        EVC statistics type: 1 - bytes/UNI_A, 2 - bytes/UNI_Z
                        , 3 - packets/UNI_A, 4 - packets/UNI_Z
```

Examples:

List the switches (useful for zabbix LLD):
```
# /usr/share/zabbix/externalscripts/kytos_zabbix.py -o 1 -z 2 | python3 -m json.tool
{
    "data": [
        {
            "{#OFSWID}": "00:00:00:00:00:00:00:11",
            "{#OFSWNAME}": "00:00:00:00:00:00:00:11"
        },
        {
            "{#OFSWID}": "00:00:00:00:00:00:00:12",
            "{#OFSWNAME}": "00:00:00:00:00:00:00:12"
        },
        {
            "{#OFSWID}": "00:00:00:00:00:00:00:22",
            "{#OFSWNAME}": "00:00:00:00:00:00:00:22"
        }
    ]
}
```

List the EVCs:

```
# /usr/share/zabbix/externalscripts/kytos_zabbix.py -o 3 -z 2 | python3 -m json.tool
{
    "data": [
        {
            "{#EVCID}": "0c6c170554ca4c",
            "{#EVCNAME}": "VLAN407_SomeDescription"
        },
        {
            "{#EVCID}": "20fa32ec9bae49",
            "{#EVCNAME}": "My EVC based on vlan 55"
        },
        {
            "{#EVCID}": "fc7da5b78bd243",
            "{#EVCNAME}": "evc-vlan-408"
        }
    ]
}
```

Get byte count for a specific EVC:

```
# /usr/share/zabbix/externalscripts/kytos_zabbix.py -o 4 -t db608c96f05940 -s 1
22594145833
# /usr/share/zabbix/externalscripts/kytos_zabbix.py -o 4 -t db608c96f05940 -s 2
22594175814
```

Leveraging the above functions you can create a Zabbix template and dashboards to better monitor your Kytos-ng instance! At AmLight/FIU we have created our Kytos template for zabbix and some dashboards, please [`contact us`](https://www.amlight.net) if you are interested.
