"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.functions = exports.Function = void 0;
var r2pipe_1 = require("r2pipe");
var Function = /** @class */ (function () {
    function Function(addr, name) {
        this.addr = addr;
        this.name = name;
    }
    Function.prototype.toString = function () {
        return "Name: ".concat(this.name, " at ").concat(this.addr);
    };
    return Function;
}());
exports.Function = Function;
function functions() {
    var r2 = r2pipe_1.default.open();
    console.log(r2.cmd("x 64"));
    // r2.close();
    var funcs = new Array();
    funcs.push(new Function(0x32, "main"));
    return funcs;
}
exports.functions = functions;
