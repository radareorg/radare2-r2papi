Typescript implementation of r2papi
===================================

This directory contains the source for the `r2papi` node module.

It provides a high level API on top of r2pipe to have a more
idiomatic way to write your r2 scripts, the module can be used
from TypeScript or Javascript and it offers autocompletion when
used with an editor with a language server (lsp).

This module is included in the default installation of radare2
starting in versoin 5.8.0. This means that you can use it directly
from the r2 shell when using the `js` command, so there's no need
to ship NodeJS to run them.

Bear in mind that r2's javascript engine doesn't offer the same
APIs as NodeJS, and despite there's a plan to make it more compatible
it is relying on radare2 APIs and its own sandbox configuration.

* `[-----]` esil emulation api
* `[x----]` NativePointer from Frida
* `[x----]` Shell
* `[xx---]` requirejs
* `[xxx--]` Base64
* `[xxx--]` r2pipe

--pancake
