"use strict";
exports.__esModule = true;
var world_js_1 = require("./world.js");
var r2papi_1 = require("r2papi");
Main();
function Main() {
    var r = r2papi_1.r2.cmd("?E Hello World");
    console.log(r);
    var papi = new r2papi_1.R2Papi(r2papi_1.r2);
    var info = papi.binInfo();
    console.log(info.machine);
    console.log("Hello " + (0, world_js_1.world)());
    var shell = papi.getShell();
    shell.chdir("/");
    var files = shell.ls();
    for (var _i = 0, files_1 = files; _i < files_1.length; _i++) {
        var file = files_1[_i];
        console.log(file);
    }
}
