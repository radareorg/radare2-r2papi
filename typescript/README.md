# Typescript APIs for radare2

The r2papi module implements a set of idiomatic and high-level APIs
that are based on top of the minimalistic `r2pipe` API.

The constructor of the `R2Papi` class takes an actual r2pipe instance,
which only requires the `.cmd()` method to interface with radare2.

The whole r2papi module is documented and integrates well with any
editor with LSP support (like Visual Studio Code or

R2Papi relies on commands and functionalities that were implemented
around r2-5.8.x, so take this into account and update your software!

Note that TypeScript usually transpiles to Javascript, and as long as
r2 ships it's own javascript runtime (based on QuickJS, which is ES6)
it is possible to run the resulting r2papi scripts without any extra
dependency in your system.

But that does not mean that you need r2 to use r2papi, you can also
use this module from NodeJS, Bun, Frida and even r2frida-compile!

--pancake
