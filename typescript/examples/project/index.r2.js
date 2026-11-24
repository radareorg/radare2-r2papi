📦
584 /index.js.map
245 /index.js
11 /index.d.ts
188 /lib/trace.d.ts
692 /lib/trace.js.map
425 /lib/trace.js
217 /node_modules/r2pipe/index.js
↻ r2pipe
40 /shell.d.ts
238 /shell.js.map
65 /shell.js
✄
{"version":3,"file":"index.js","sourceRoot":"/Users/pancake/prg/radare2-r2papi/typescript/examples/project/","sources":["index.ts"],"names":[],"mappings":"AAAA,OAAO,MAAM,MAAM,YAAY,CAAC;AAChC,OAAO,EAAE,SAAS,EAAY,MAAM,gBAAgB,CAAC;AAErD,OAAO,CAAC,GAAG,CAAC,aAAa,CAAC,CAAC;AAC3B,MAAM,KAAK,GAAG,SAAS,EAAE,CAAC;AAC1B,OAAO,CAAC,GAAG,CAAC,KAAK,CAAC,GAAG,CAAC,CAAC,CAAC,EAAC,EAAE,CAAA,CAAC,CAAC,QAAQ,EAAE,CAAC,CAAC,IAAI,CAAC,IAAI,CAAC,CAAC,CAAC;AACrD,OAAO,CAAC,GAAG,CAAC,KAAK,CAAC,GAAG,CAAC,CAAC,CAAC,EAAC,EAAE,CAAA,EAAE,GAAC,CAAC,CAAC,CAAC,IAAI,CAAC,EAAE,CAAC,CAAC,CAAC;AAE3C,MAAM,EAAE,CAAC"}
✄
import prompt from "./shell.js";
import { functions } from "./lib/trace.js";
console.log("Hello World");
const funcs = functions();
console.log(funcs.map((f) => f.toString()).join("\n"));
console.log(funcs.map((f) => "" + f).join(""));
prompt();
✄
export {};

✄
export declare class Function {
    addr: number;
    name: string;
    constructor(addr: number, name: string);
    toString(): string;
}
export declare function functions(): [Function];

✄
{"version":3,"file":"trace.js","sourceRoot":"/Users/pancake/prg/radare2-r2papi/typescript/examples/project/","sources":["lib/trace.ts"],"names":[],"mappings":"AAAA,OAAO,MAAM,MAAM,QAAQ,CAAC;AAE5B,MAAM,OAAO,QAAQ;IAIpB,YAAa,IAAW,EAAE,IAAY;QACrC,IAAI,CAAC,IAAI,GAAG,IAAI,CAAC;QACjB,IAAI,CAAC,IAAI,GAAG,IAAI,CAAC;IAClB,CAAC;IACD,QAAQ;QACP,OAAO,SAAS,IAAI,CAAC,IAAI,OAAO,IAAI,CAAC,IAAI,EAAE,CAAC;IAC7C,CAAC;CACD;AAED,MAAM,UAAU,SAAS;IACxB,MAAM,EAAE,GAAG,MAAM,CAAC,IAAI,EAAE,CAAC;IACzB,OAAO,CAAC,GAAG,CAAC,EAAE,CAAC,GAAG,CAAC,MAAM,CAAC,CAAC,CAAC;IAC5B,cAAc;IACd,MAAM,KAAK,GAAG,IAAI,KAAK,EAAgB,CAAC;IACxC,KAAK,CAAC,IAAI,CAAC,IAAI,QAAQ,CAAC,IAAI,EAAE,MAAM,CAAC,CAAC,CAAC;IACvC,OAAO,KAAK,CAAC;AACd,CAAC"}
✄
import r2pipe from "r2pipe";
export class Function {
    constructor(addr, name) {
        this.addr = addr;
        this.name = name;
    }
    toString() {
        return `Name: ${this.name} at ${this.addr}`;
    }
}
export function functions() {
    const r2 = r2pipe.open();
    console.log(r2.cmd("x 64"));
    // r2.close();
    const funcs = new Array();
    funcs.push(new Function(0x32, "main"));
    return funcs;
}
✄
// if nodejs then require (r2pipe.orig");

class R2PipeInstance() {
	constructor() {
	}
	cmd(s: string) string {
		return "";
	}
}

module.exports = {
	open: function() {
	      return new R2PipeInstance();
      }
}

✄
export default function prompt(): void;

✄
{"version":3,"file":"shell.js","sourceRoot":"/Users/pancake/prg/radare2-r2papi/typescript/examples/project/","sources":["shell.ts"],"names":[],"mappings":"AAAA,MAAM,CAAC,OAAO,UAAU,MAAM;IAC7B,OAAO,CAAC,GAAG,CAAC,UAAU,CAAC,CAAC;AACzB,CAAC"}
✄
export default function prompt() {
    console.log("r2test> ");
}