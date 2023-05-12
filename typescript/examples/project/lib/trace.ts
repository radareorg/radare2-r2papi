import r2pipe from "r2pipe";

export class Function {
	addr: number;
	name: string;

	constructor (addr:number, name: string) {
		this.addr = addr;
		this.name = name;
	}
	toString() {
		return `Name: ${this.name} at ${this.addr}`;
	}
}

export function functions() : [Function] {
	const r2 = r2pipe.open();
	console.log(r2.cmd("x 64"));
	// r2.close();
	const funcs = new Array() as [Function];
	funcs.push(new Function(0x32, "main"));
	return funcs;
}
