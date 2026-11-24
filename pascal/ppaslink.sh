#!/bin/sh
DoExitAsm ()
{ echo "An error occurred while assembling $1"; exit 1; }
DoExitLink ()
{ echo "An error occurred while linking $1"; exit 1; }
OFS=$IFS
IFS="
"
/Applications/Xcode.app/Contents/Developer/usr/bin/ld        -x   -multiply_defined suppress -L. -o hello `cat link81818.res` -filelist linkfiles81818.res
if [ $? != 0 ]; then DoExitLink ; fi
IFS=$OFS
