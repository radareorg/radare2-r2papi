// optimizations for esil ast
import { EsilParser } from "./esil";

// Type 'R2Pipe' is missing the following properties from type 'R2Pipe': cmdj, callj, plugin, unload
// import { R2Pipe } from "./r2pipe";
declare let r2: any;

export function plusZero() {}

function traverse(ep: EsilParser, child: any) {
    for (const child of ep.nodes) {
        if (child) {
            traverse(ep, child);
        }
        traverse(ep, child);
    }
}

const ep = new EsilParser(r2);
ep.parseFunction();
ep.parse("0,eax,+,ebx,:=");
traverse(ep, null);
console.log("DO");
console.log(ep.toString());
console.log("NE");
