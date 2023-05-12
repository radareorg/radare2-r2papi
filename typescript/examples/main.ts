// import {R2Pipe} from "r2papi";
declare type R2Pipe = any;
declare let r2: any;

declare var Gmain: Function | null;

console.log("main");
try {
	Gmain
} catch (e) {
	var Gmain : Function | null = null;
}
Gmain = function (r2: R2Pipe, args: any) {
	console.log(Object.keys(args));
	const res = r2.cmd("x");
	console.log("Hello World", res);
}
console.log("pre");
Gmain(r2, []);
console.log("pos");
