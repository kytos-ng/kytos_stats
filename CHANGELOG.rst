#########
Changelog
#########
All notable changes to the kytos_stats NApp will be documented in this file.

[UNRELEASED] - Under development
********************************
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

Security
========

General Information
===================
- This napp was cloned from ``flow_stats``.
- ``@rest`` endpoints run by ``starlette/uvicorn`` instead of ``flask/werkzeug``.
