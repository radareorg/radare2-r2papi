Development guide
=================

Introduction
------------

The ``r2pipe-api`` tries to abstract radare functionalities, there's a class
(or there will be at some point) representing each major feature that it have.

`r2pipe`_ is used to communicate to an underlying ``radare2`` process. Working
with ``r2pipe`` is really simple, it just have three methods ``open``, ``cmd``
and ``cmdj``.

* ``open``: Opens a binary, memory dump, malloc:// or anything that r2
  supports. Returns an ``OpenBase`` object.
* ``cmd``: Method of ``OpenBase``, it executes a r2 command, and returns its
  output as a string.
* ``cmdj``: The same as ``cmd``, but interpret the output as json, and return a
  python native object.

An example:

.. code-block:: python

    >>> import r2pipe
    >>> r = r2pipe.open('/bin/ls')
    >>> r.cmd('i~arch')
    'arch     x86\nmachine  AMD x86-64 architecture'
    >>> r.cmdj('ij')['bin']['arch']
    'x86'


:ref:`R2Api` contains instances of all the classes implementing radare
functionalities (:ref:`Print`, :ref:`Debugger`, :ref:`Esil`...). And they are
available under ``R2Api.print``, ``R2Api.debugger``...
This objects also can contain subclasses, to be more intuitive, one example is
the debugger: ``R2Api.debugger.cpu``.

Development Environment
-----------------------

It is recommended to use a virtual environment while developing (or using)
r2pipe-api, this will help you maintain your system clean and avoid problems
with dependencies.

Use the following code to create a new virtual environment, and to start using
it.

.. code-block:: bash

    $ python3 -m venv r2api-venv
    $ source r2api-venv/bin/activate
    (r2api-venv) $ # Now you are in the virtual environment, make sure pip is updated
    (r2api-venv) $ pip install --upgrade pip

Now that a clean virtual environment have been created, install r2pipe-api.

.. code-block:: bash

    (r2api-venv) $ git clone https://github.com/radare/radare2-r2pipe-api/
    (r2api-venv) $ cd radare2-r2pipe-api/python
    (r2api-venv) $ pip install -e .

Everything is ready to start contributing to r2pipe-api!

Testing
-------

Ideally, there should be a test for each functionallity.

There are two dependencies for testing, `pytest` and `pytest-cov`. They can be
installed with `pip`.

.. code-block:: bash

    (r2api-venv) $ pip install pytest pytest-cov

Tests are organized in different files, one for each radare2 functionality. They
are found under `radare2-r2pipe-api/python/test` path. There is a Makefile used
to execute the tests and get the coverage metrics, just execute `make`.

Once all the tests have finished, open `htmlcov/index.html` to see the code
coverage that is achieved.

Documentation
-------------

The API must be documented, and Sphinx is used for this. When documenting a
method, class, or module, use `rst` syntax so Sphinx can autogenerate the docs.

Remember to install sphinx first:

.. code-block:: bash

    (r2api-venv) $ pip install sphinx

Documentation can be built executing `make html` in
`radare2-r2pipe-api/python/docs`, then open `_build/html/index.html`.

Base Class
----------

There's a base class :ref:`R2Base` that implements the basic stuff needed:

* Temporal seek (like r2 command ``@``)
* Command execution

Almost all the classes inherits from it.

.. _r2pipe: https://github.com/radare/radare2-r2pipe
