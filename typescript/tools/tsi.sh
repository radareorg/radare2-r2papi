#!/bin/sh
# typescript interface from js
CMD="$1"
FILE=/bin/ls
export RES=`r2 -qc "af;$CMD" $FILE`
node -e 'console.log(require("json2ts").convert(process.env.RES));'
# XXX the name of the interface must be defined somehow
