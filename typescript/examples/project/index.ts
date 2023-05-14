import prompt from "./shell.js";
import { functions, Function } from "./lib/trace.js";

console.log("Hello World");
const funcs = functions();
console.log(funcs.map((f)=>f.toString()).join("\n"));
console.log(funcs.map((f)=>""+f).join(""));

prompt();
