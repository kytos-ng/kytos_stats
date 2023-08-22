#########
Changelog
#########
All notable changes to the kytos_stats NApp will be documented in this file.

[UNRELEASED] - Under development
********************************

[2023.1.0] - 2023-06-27
***********************

Added
=====
- Event ``kytos/of_core.table_stats.received``.
- Update ``scripts/kytos_zabbix.py`` script to add table stats. In particular, ``zabbix_wrapper`` prints the ``active_count`` field, which is used for capacity planning.
- Add GET ``v1/table/stats`` endpoint to listing table stats by dpid.

General Information
===================
- This napp was cloned from ``flow_stats``.
- ``@rest`` endpoints run by ``starlette/uvicorn`` instead of ``flask/werkzeug``.
