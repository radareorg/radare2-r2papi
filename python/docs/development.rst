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

A little example:

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

Base Class
----------

There's a base class :ref:`R2Base` that implements the basic stuff needed:

* Temporal seek (like r2 command ``@``)
* Command execution

Almost all the classes inherits from it.

.. _r2pipe: https://github.com/radare/radare2-r2pipe
