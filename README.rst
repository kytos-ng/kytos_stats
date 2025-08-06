|Stable| |Tag| |License| |Build| |Coverage| |Quality|

.. raw:: html

  <div align="center">
    <h1><code>amlight/kytos_stats</code></h1>

    <strong> Napp responsible for providing statistics. </strong>

    <h3><a href="https://kytos-ng.github.io/api/kytos_stats.html">OpenAPI Docs</a></h3>
  </div>


Overview
========
Napp responsible for providing statistics.

Installing
========== 

To install this NApp, first, make sure to have the same venv activated as you have ``kytos`` installed on:

.. code:: shell

   $ git clone https://github.com/amlight/kytos_stats.git
   $ cd kytos_stats
   $ python3 -m pip install --editable .

To install the kytos environment, please follow our
`development environment setup <https://github.com/kytos-ng/documentation/blob/master/tutorials/napps/development_environment_setup.rst>`_.

Features
========
- REST API to list flows statistics by switch
- REST API to list tables statistics by switch
- REST API to get flows statistics (packet_count and bytes_count) of an specific flow
- REST API to get flows statistics (packet_count and bytes_count) for a switch
- Handle flow stats messages when replies are received
- Handle table stats messages when replies are received

Requirements
============

- `kytos/of_core <https://github.com/kytos-ng/of_core>`

Events
======

Subscribed
----------

- ``kytos/of_core.flow_stats.received``
- ``kytos/of_core.table_stats.received``
- ``kytos/of_core.port_stats``


.. TAGs

.. |Stable| image:: https://img.shields.io/badge/stability-stable-green.svg
   :target: https://github.com/kytos-ng/kytos_stats
.. |License| image:: https://img.shields.io/github/license/kytos-ng/kytos_stats.svg
   :target: https://github.com/kytos-ng/kytos_stats/blob/master/LICENSE
.. |Tag| image:: https://img.shields.io/github/tag/kytos-ng/kytos_stats.svg
   :target: https://github.com/kytos-ng/kytos_stats/tags
.. |Build| image:: https://scrutinizer-ci.com/g/kytos-ng/kytos_stats/badges/build.png?b=master
  :alt: Build status
  :target: https://scrutinizer-ci.com/g/kytos-ng/kytos_stats/?branch=master
.. |Coverage| image:: https://scrutinizer-ci.com/g/kytos-ng/kytos_stats/badges/coverage.png?b=master
  :alt: Code coverage
  :target: https://scrutinizer-ci.com/g/kytos-ng/kytos_stats/?branch=master
.. |Quality| image:: https://scrutinizer-ci.com/g/kytos-ng/kytos_stats/badges/quality-score.png?b=master
  :alt: Code-quality score
  :target: https://scrutinizer-ci.com/g/kytos-ng/kytos_stats/?branch=master



