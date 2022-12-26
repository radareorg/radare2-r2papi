// r2papi main file

import { R2PapiShell } from "./shell.js";

export type InstructionType = "mov" | "jmp" | "cmp" | "nop" | "call";
export type InstructionFamily = "cpu" | "fpu" | "priv";

export interface SearchResult {
	offset: number; // TODO: rename to addr
	type: string;
	data: string;
};

export interface DebugModule {
	base: string;
	name: string;
	path: string;
	size: number;
};

export interface Flag {
	name: string;
	size: number;
	offset: number;
};

// XXX not working? export type ThreadState = "waiting" | "running" | "dead" ;
export interface ThreadContext {
	context: any;
	id: number;
	state: string;
	selected: boolean;
}

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
	call(cmd: string): string;
	callj(cmd: string): any;
	log(msg: string): string;
}

export class R2Papi {
	public r2: R2Pipe;

	constructor(r2: R2Pipe) {
		this.r2 = r2;
	}
	getShell(): R2PapiShell {
		return new R2PapiShell (this);
	}
	printAt(msg: string, x: number, y: number) : void{
		// see pg, but pg is obrken :D
	}

	clearScreen() : void {
		this.r2.cmd("!clear");
	}

	getConfig(key: string) : string {
		return this.r2.call("e " + key).trim();
	}

	setConfig(key: string, val: string) : void {
		this.r2.call("e " + key + "=" + val);
	}

	getRegisters(): any {
		// this.r2.log("winrar" + JSON.stringify(JSON.parse(this.r2.cmd("drj")),null, 2) );
		return this.cmdj("drj");
	}
	enumerateThreads() : ThreadContext[] {
		// TODO: use apt/dpt to list threads at iterate over them to get the registers
		const regs0 = this.cmdj("drj");
		const thread0 = {
			context: regs0,
			id: 0,
			state: "waiting",
			selected: true,
		};
		return [thread0];
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
	searchBytes(data: number[]): SearchResult[] {
		function num2hex(data: number) : string {
			return (data & 0xff).toString(16);
		}
		const s = data.map(num2hex).join('');
		const res: SearchResult[] = this.cmdj("/xj " + s);
		return res;
	}
	binInfo(): BinFile {
		try {
			return this.cmdj("ij~{bin}");
		} catch (e: any) {
			return {} as BinFile;
		}
	}
	enumerateModules() : DebugModule[] {
		return this.callj("dmmj");
	}
	skip() {
		this.r2.cmd("dss");
	}
	ptr(s: string | number): NativePointer {
		return new NativePointer(s, this);
	}
	call(s: string): string {
		return this.r2.call(s);
	}
	callj(s: string): any {
		return JSON.parse(this.call(s));
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
	constructor(s: string | number, api?: R2Papi) {
		if (api === undefined) {
			this.api = R;
		} else {
			this.api = api;
		}
		// this.api.r2.log("NP " + s);
		this.addr = ("" + s).trim();
	}

	readByteArray(len: number) : number[] {
		return JSON.parse(this.api.cmd(`p8j ${len}@${this.addr}`));
	}
	and(a: number): NativePointer {
		this.addr = this.api.call(`?v ${this.addr} & ${a}`).trim();
		return this;
	}
	or(a: number): NativePointer {
		this.addr = this.api.call(`?v ${this.addr} | ${a}`).trim();
		return this;
	}
	add(a: number): NativePointer {
		this.addr = this.api.call(`?v ${this.addr}+${a}`).trim();
		return this;
	}
	sub(a: number): NativePointer {
		this.addr = this.api.call(`?v ${this.addr}-${a}`).trim();
		return this;
	}
	writeByteArray(data: number[]): NativePointer {
		this.api.cmd("wx " + data.join(""))
		return this;
	}
	writeAssembly(instruction: string) : NativePointer {
		this.api.cmd(`\"wa ${instruction} @ ${this.addr}`);
		return this;
	}
	writeCString(s: string): NativePointer {
		this.api.cmd("\"w " + s + "\"");
		return this;
	}
	isNull(): boolean {
		return +this.addr === 0;
	}
	compare(a : string|number|NativePointer) {
		if (typeof a === "string" || typeof a === "number") {
			a = new NativePointer(a);
		}
		return a.addr === this.addr;
	}
	pointsToNull(): boolean {
		return this.readPointer().compare(0);
	}
	toString() :string {
		return this.addr.trim();
	}
	writePointer(p: NativePointer) : void {
		const cmd = (+this.api.getConfig("asm.bits") === 64)? "wv8": "wv4";
		this.api.cmd(`${cmd} ${p}@${this}`);
		// 5.8.2 this.call("wvp " + p.addr);
	}
	readPointer() : NativePointer {
		if (+this.api.getConfig("asm.bits") === 64) {
			return new NativePointer(this.api.call("pv8@" + this.addr));
		} else {
			return new NativePointer(this.api.call("pv4@" + this.addr));
		}
	}
	readU8(): number {
		return +this.api.cmd(`pv1@"${this.addr}`);
	}
	readU16(): number {
		return +this.api.cmd(`pv2@"${this.addr}`);
	}
	readU32(): number {
		return +this.api.cmd(`pv4@"${this.addr}`);
	}
	readU64(): number {
		// XXX: use bignum or 
		return +this.api.cmd(`pv8@"${this.addr}`);
	}
	writeInt(n:number): number {
		return +this.api.cmd(`wv4 ${n}@${this.addr}`);
	}
	writeU8(n: number) : boolean {
		this.api.cmd(`wv1 ${n}@${this.addr}`);
		return true;
	}
	writeU16(n: number) : boolean {
		this.api.cmd(`wv2 ${n}@${this.addr}`);
		return true;
	}
	writeU32(n: number) : boolean {
		this.api.cmd(`wv4 ${n}@${this.addr}`);
		return true;
	}
	writeU64(n: number) : boolean {
		this.api.cmd(`wv8 ${n}@${this.addr}`);
		return true;
	}
	readInt(): number {
		return +this.api.cmd(`pv4@"${this.addr}`);
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

export class Base64 {
	static encode(x: string) : string {
		return b64(x);
	}
	static decode(x: string) : string {
		return b64(x, true);
	}
}

interface base64Interface{
    (message: string, decode?: boolean):string;
}
export declare var b64: base64Interface;
export declare var r2: R2Pipe;
export declare var R: R2Papi;

