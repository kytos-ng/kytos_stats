|Tag| |License|

.. raw:: html

  <div align="center">
    <h1><code>amlight/flow_stats</code></h1>

    <strong> Napp responsible for providing a Generic Flow and stats </strong>

    <h3><a href="https://kytos-ng.github.io/api/flow_stats.html">OpenAPI Docs</a></h3>
  </div>


Overview
========
Napp responsible for providing a Generic Flow and stats 

Installing
==========

To install this NApp, first, make sure to have the same venv activated as you have ``kytos`` installed on:

.. code:: shell

   $ git clone https://github.com/amlight/flow_stats.git
   $ cd flow_stats
   $ python setup.py develop

Requirements
============

- `kytos/of_core <https://github.com/kytos-ng/of_core>`_


Events
======

Subscribed
----------

- ``kytos/of_core.v0x01.messages.in.ofpt_stats_reply``
- ``kytos/of_core.v0x04.messages.in.ofpt_multipart_reply``


.. TAGs

.. |License| image:: https://img.shields.io/github/license/amlight/flow_stats.svg
   :target: https://github.com/amlight/flow_stats/blob/master/LICENSE
.. |Build| image:: https://scrutinizer-ci.com/g/amlight/flow_stats/badges/build.png?b=master
  :alt: Build status
  :target: https://scrutinizer-ci.com/g/amlight/flow_stats/?branch=master
.. |Coverage| image:: https://scrutinizer-ci.com/g/amlight/flow_stats/badges/coverage.png?b=master
  :alt: Code coverage
  :target: https://scrutinizer-ci.com/g/amlight/flow_stats/?branch=master
.. |Quality| image:: https://scrutinizer-ci.com/g/amlight/flow_stats/badges/quality-score.png?b=master
  :alt: Code-quality score
  :target: https://scrutinizer-ci.com/g/amlight/flow_stats/?branch=master
.. |Stable| image:: https://img.shields.io/badge/stability-stable-green.svg
   :target: https://github.com/amlight/flow_stats
.. |Tag| image:: https://img.shields.io/github/tag/amlight/flow_stats.svg
   :target: https://github.com/amlight/flow_stats/tags
