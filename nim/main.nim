import r2papi
import std/strformat
import std/sugar
import std/json

var r = r2papi.R2Papi()
r.speak ("Hello World")

var bigint = 0xeeff_ffff_ffff_fff0

var o = r.cmdj("ij");
var fileName = o["core"]["file"].str
echo(fileName)

echo(fmt"{bigint:+x}")

# echo("Hello World")
# echo(r2cmd("x"))

