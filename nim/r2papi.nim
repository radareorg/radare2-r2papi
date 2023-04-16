import std/[json, options, sugar]

proc r2cmd(arg: cstring): cstring {.importc}

type R2Papi = object

proc cmdj(self: R2Papi, cmd: string): JsonNode = 
  var res = $r2cmd(cmd)
  return parseJson(res)

proc speak(self: R2Papi, msg: string) = 
  echo r2cmd("?E " & msg)

export r2cmd, cmdj, R2Papi, speak
