#########
Changelog
#########
All notable changes to the kytos_stats NApp will be documented in this file.

[UNRELEASED] - Under development
********************************

[2025.1.0] - 2024-04-14
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
