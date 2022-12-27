import {R2Pipe} from "r2papi";

declare var Gmain: Function;

console.log("main");
Gmain = function (r2: R2Pipe, args: any) {
	console.log(Object.keys(args));
	const res = r2.cmd("x");
	console.log("Hello World", res);
}
console.log("pre");
Gmain();
console.log("pos");
