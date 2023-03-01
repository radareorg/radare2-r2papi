import { world } from "./world.js";
import { r2, R2Papi } from "r2papi";

Main();

function Main() {
	var r = r2.cmd("?E Hello World");
	console.log(r);
	var papi = new R2Papi(r2);
	const info = papi.binInfo();
	console.log(info.machine);
	console.log("Hello " + world());

	const shell = papi.getShell();
	shell.chdir("/");
	const files = shell.ls();
	for (let file of files) {
		console.log(file);
	}
}
