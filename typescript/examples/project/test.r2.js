📦
327 /index.js.map
133 /index.js
11 /index.d.ts
188 /lib/trace.d.ts
539 /lib/trace.js.map
314 /lib/trace.js
40 /shell.d.ts
238 /shell.js.map
65 /shell.js
✄
{"version":3,"file":"index.js","sourceRoot":"/Users/pancake/prg/radare2-r2papi/typescript/examples/project/","sources":["index.ts"],"names":[],"mappings":"AAAA,OAAO,MAAM,MAAM,YAAY,CAAC;AAChC,OAAO,EAAE,SAAS,EAAY,MAAM,gBAAgB,CAAC;AAErD,MAAM,KAAK,GAAG,SAAS,EAAE,CAAC;AAC1B,OAAO,CAAC,GAAG,CAAC,KAAK,CAAC,CAAC;AACnB,MAAM,EAAE,CAAC"}
✄
import prompt from "./shell.js";
import { functions } from "./lib/trace.js";
const funcs = functions();
console.log(funcs);
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
{"version":3,"file":"trace.js","sourceRoot":"/Users/pancake/prg/radare2-r2papi/typescript/examples/project/","sources":["lib/trace.ts"],"names":[],"mappings":"AAAA,MAAM,OAAO,QAAQ;IAIpB,YAAa,IAAW,EAAE,IAAY;QACrC,IAAI,CAAC,IAAI,GAAG,IAAI,CAAC;QACjB,IAAI,CAAC,IAAI,GAAG,IAAI,CAAC;IAClB,CAAC;IACD,QAAQ;QACP,OAAO,SAAS,IAAI,CAAC,IAAI,OAAO,IAAI,CAAC,IAAI,EAAE,CAAC;IAC7C,CAAC;CACD;AAED,MAAM,UAAU,SAAS;IACxB,MAAM,KAAK,GAAG,IAAI,KAAK,EAAgB,CAAC;IACxC,KAAK,CAAC,IAAI,CAAC,IAAI,QAAQ,CAAC,IAAI,EAAE,MAAM,CAAC,CAAC,CAAC;IACvC,OAAO,KAAK,CAAC;AACd,CAAC"}
✄
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
    const funcs = new Array();
    funcs.push(new Function(0x32, "main"));
    return funcs;
}
✄
export default function prompt(): void;

✄
{"version":3,"file":"shell.js","sourceRoot":"/Users/pancake/prg/radare2-r2papi/typescript/examples/project/","sources":["shell.ts"],"names":[],"mappings":"AAAA,MAAM,CAAC,OAAO,UAAU,MAAM;IAC7B,OAAO,CAAC,GAAG,CAAC,UAAU,CAAC,CAAC;AACzB,CAAC"}
✄
export default function prompt() {
    console.log("r2test> ");
}