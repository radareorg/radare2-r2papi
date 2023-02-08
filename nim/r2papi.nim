
proc r2cmd(arg: cstring): cstring {.importc}

type R2Papi = object

proc speak(self: R2Papi, msg: string) = 
  echo r2cmd("?E " & msg)

export r2cmd, R2Papi, speak
