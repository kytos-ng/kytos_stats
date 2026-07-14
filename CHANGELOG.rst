#########
Changelog
#########
All notable changes to the kytos_stats NApp will be documented in this file.

[UNRELEASED] - Under development
********************************

Added
=====
- Event listener for ``kytos/topology.switch.deleted`` to evict all cached
  flow, table and port stats of a deleted switch.

Changed
=======
- Stats event handlers (``flow_stats.received``, ``table_stats.received``) now
  run asynchronously via ``alisten_to``.

Fixed
=====
- Fixed unbounded memory growth of the flow, table and port stats caches. Each
  stats reply now overwrites the reporting switch's cached data instead of
  merging into it.

[2025.2.0] - 2026-02-02
***********************

Added
=====
- Event listner for ``kytos/of_core.port_stats`.
- Add GET ``v1/port/stats`` endpoint to listing port stats by dpid and port.

Fixed
=====
- Fixed openapi.yml rendering

[2025.1.0] - 2025-04-14
***********************

No major changes since the last release.

[2024.1.0] - 2024-07-23
***********************

Changed
=======
- Updated python environment installation from 3.9 to 3.11

[2023.1.0] - 2023-06-27
***********************

Added
=====
- Event ``kytos/of_core.table_stats.received``.
- Update ``scripts/kytos_zabbix.py`` script to add table stats. In particular, ``zabbix_wrapper`` prints the ``active_count`` field, which is used for capacity planning.
- Add GET ``v1/table/stats`` endpoint to listing table stats by dpid.

Changed
=======

Deprecated
==========

Removed
=======

Fixed
=====
- Fixed error due to division by zero when ``duration_sec` is zero in the ``stats`` of a flow.

Security
========

General Information
===================
- This napp was cloned from ``flow_stats``.
- ``@rest`` endpoints run by ``starlette/uvicorn`` instead of ``flask/werkzeug``.
