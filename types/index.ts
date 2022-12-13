export type InstructionType = "mov" | "jmp" | "cmp" | "nop" | "call";
export type InstructionFamily = "cpu" | "fpu" | "priv";

export interface SearchResult {
	offset: number;
	type: string;
	data: string;
};

export interface Flag {
	name: string;
	size: number;
	offset: number;
};

export interface CallRef {
	addr: number;
	type: string;
	at: number;
};

export interface Function {
	offset: number;
	name: string;
	size: number;
	noreturn: boolean;
	stackframe: number;
	ebbs: number;
	signature: string;
	nbbs: number;
	callrefs: CallRef[];
	codexrefs: CallRef[];
};

export interface BinFile {
	arch: string;
	static: boolean;
	va: boolean;
	stripped: boolean;
	pic: boolean;
	relocs: boolean;
	sanitize: boolean;
	baddr: number;
	binsz: number;
	bintype: string;
	bits: number;
	canary: boolean;
	class: string;
	compiler: string;
	endian: string;
	machine: string;
	nx: boolean;
	os: string;
	laddr: number;
	linenum: boolean;
	havecode: boolean;
	intrp: string;

};

export interface Reference {
	from: number;
	type: string;
	perm: string;
	opcode: string;
	fcn_addr: number;
	fcn_name: string;
	realname: string;
	refname: string;
};

export interface BasicBlock {
	addr: number,
	size: number,
	jump: number,
	fail: number,
	opaddr: number,
	inputs: number,
	outputs: number,
	ninstr: number,
	instrs: number[],
	traced: boolean
};

export interface Instruction {
	type: InstructionType;
	addr: number;
	opcode: string;
	pseudo: string;
	mnemonic: string;
	sign: boolean;
	family: InstructionFamily;
	description: string;
	esil: string;
	opex: any;
	size: number;
	ptr: number;
	bytes: string;
	id: number;
	refptr: number;
	direction: "read" | "write";
	stackptr: number;
	stack: string; // "inc"|"dec"|"get"|"set"|"nop"|"null"; 
}

export interface R2Pipe {
	cmd(cmd: string): string;
	cmdj(cmd: string): any;
	log(msg: string): string;
}

export class R2Papi {
	public r2: R2Pipe;

	constructor(r2: R2Pipe) {
		this.r2 = r2;
	}

	clearScreen() {
		this.r2.cmd("!clear");
	}
	getRegisters(): any {
		// this.r2.log("winrar" + JSON.stringify(JSON.parse(this.r2.cmd("drj")),null, 2) );
		return this.cmdj("drj");
	}
	setRegisters(obj: any) {
		for (let r of Object.keys(obj)) {
			const v = obj[r];
			this.r2.cmd("dr " + r + "=" + v);
		}
	}
	analyzeProgram(): void {
		this.r2.cmd("aa");
	}
	hex(s: number | string): string {
		return this.r2.cmd("?v " + s).trim();
	}
	step(): R2Papi {
		this.r2.cmd("ds");
		return this;
	}
	stepOver(): R2Papi {
		this.r2.cmd("dso");
		return this;
	}
	math(expr: number | string): number {
		return +this.r2.cmd("?v " + expr);
	}
	searchString(s: string): SearchResult[] {
		const res: SearchResult[] = this.cmdj("/j " + s);
		return res;
	}
	binInfo(): BinFile {
		try {
			return this.cmdj("ij~{bin}");
		} catch (e: any) {
			return {} as BinFile;
		}
	}
	skip() {
		this.r2.cmd("dss");
	}
	ptr(s: string | number): NativePointer {
		return new NativePointer(this, s);
	}
	cmd(s: string): string {
		return this.r2.cmd(s);
	}
	cmdj(s: string): any {
		return JSON.parse(this.cmd(s));
	}
	log(s: string) {
		return this.r2.log(s);
	}
	clippy(msg: string): void {
		this.r2.log(this.r2.cmd("?E " + msg));
	}
	ascii(msg: string): void {
		this.r2.log(this.r2.cmd("?ea " + msg));
	}
	listFunctions() : Function[] {
		return this.cmdj("aflj");
	}
	listFlags() : Flag[] {
		return this.cmdj("fj");
	}
}

export class NativePointer {
	addr: string;
	api: R2Papi;
	constructor(api: R2Papi, s: string | number) {
		this.api = api;
		// this.api.r2.log("NP " + s);
		this.addr = "" + s;
	}
	readByteArray(len: number) {
		return JSON.parse(this.api.cmd(`p8j ${len}@${this.addr}`));
	}
	add(a: number): NativePointer {
		this.addr = this.api.cmd(`?v ${this.addr} + ${a}`);
		return this;
	}
	sub(a: number): NativePointer {
		this.addr = this.api.cmd(`?v ${this.addr} - ${a}`);
		return this;
	}
	writeCString(s: string): NativePointer {
		this.api.cmd("\"w " + s + "\"");
		return this;
	}
	readCString(): string {
		return JSON.parse(this.api.cmd(`psj@${this.addr}`)).string;
	}
	instruction(): Instruction {
		const op: any = this.api.cmdj(`aoj@${this.addr}`)[0];
		return op;
	}
	analyzeFunction() {
		this.api.cmd("af@" + this.addr);
	}
	name(): string {
		return this.api.cmd("fd " + this.addr).trim();
	}
	basicBlock(): BasicBlock {
		const bb: BasicBlock = this.api.cmdj("abj@" + this.addr);
		return bb;
	}
	functionBasicBlocks(): BasicBlock[] {
		const bbs : BasicBlock[] = this.api.cmdj("afbj@"+this.addr);
		return bbs;
	}
	xrefs(): Reference[] {
		return this.api.cmdj("axtj@" + this.addr);
	}
}


export declare var r2: R2Pipe;
export declare var R: R2Papi;
interface base64Interface{
    (message: string, decode: boolean):string;
}
export declare var b64: base64Interface;
