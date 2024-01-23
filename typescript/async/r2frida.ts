import { r2, R2Pipe } from "r2papi";

export class R2Frida {
	constructor(r2: R2Pipe) {
		console.log("Welcome to R2frida");
		if (r2.cmd("o~frida://").trim() == "") {
			throw new Error("There's no frida session available");
		}
	}

	eval(expr : string) : string {
		return r2.cmd(`"": ${expr}`);
	}
	targetDetails() : TargetDetails {
		return r2.cmdj(":ij") as TargetDetails;
	}
}

export function main() {
	console.log("Hello from r2papi-r2frida");
	const r2f = new R2Frida(r2);
	r2f.eval("console.log(123);");
	const { pid, arch, cwd } = r2f.targetDetails();
	console.log(pid, arch, cwd);
}
main();

export interface TargetDetails {
	arch: string;
	bits: number;
	os:string;
	pid: number;
	uid: number;
	runtime: string;
	objc:boolean;
	swift:boolean;
	mainLoop:boolean;
	pageSize: number;
	pointerSize: number;
	codeSigningPolicy: string;
	isDebuggerAttached: boolean;
	cwd: string;
	bundle: string;
	exename: string;
	appname: string;
	appversion: string;
	appnumversion: string;
	minOS: string;
	modulename: string;
	modulebase: string;
	homedir: string;
	tmpdir: string;
	bundledir?:any;
};
