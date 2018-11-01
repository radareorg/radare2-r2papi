Welcome to r2pipe-api's documentation!
======================================

High level API on top of r2pipe. An intuitive and easy way to use and
script radare2.

+---------+----------------------------------------------------+
| Author  | Quim <quim@airmail.cc>                             |
+---------+----------------------------------------------------+
| License | ???                                                |
+---------+----------------------------------------------------+
| Version | ???                                                |
+---------+----------------------------------------------------+

.. todo::

    What license to use?

.. todo::

    How versions will be managed

.. todo::

    I'm a terrible writer, feel free to edit wathever you want

Exposes `radare2`_ functionality through a high level python API. It's a good
way for new radare users to see the capabilities that it have, without having
to deal with commands and other CLI stuff that sometimes scares people.

The code is hosted in `github`_.

.. _radare2: https://github.com/radare/radare2
.. _github: https://github.com/radare/radare2-r2pipe-api

Install
=======

The installation process is really simple, it's not in PyPI yet, but i'll be at
some point.

Create a new virtual environment **(optional)**:

.. code-block:: shell

    $ python3 -m venv venv
    $ source venv/bin/activate
    (venv) $ pip install --upgrade pip

Install ``radare2`` from git:

.. code-block:: shell

    $ git clone https://github.com/radare/radare2
    $ cd radare2
    $ ./sys/install.sh

3. Clone the git repository and install the library with ``pip``:

.. code-block:: shell

    $ git clone https://github.com/radare/radare2-r2pipe-api
    $ cd radare2-r2pipe-api/python
    $ pip install -e .

To test if it was intalled, the following code must be executed without errors:

.. code-block:: python

    >>> from r2api import R2Api
    >>> R2Api('-')


.. toctree::
   :maxdepth: 3
   :caption: Contents:

   development
   api



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
