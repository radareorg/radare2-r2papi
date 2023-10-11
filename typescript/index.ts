// r2papi main file

import { R2PapiShell } from "./shell.js";

export type InstructionType = "mov" | "jmp" | "cmp" | "nop" | "call" | "add" | "sub";
export type InstructionFamily = "cpu" | "fpu" | "priv";
export type GraphFormat = "dot" | "json" | "mermaid" | "ascii";
export type Permission = "---" | "r--" | "rw-" | "rwx" | "r-x" | "-wx" | "--x";

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

export type PluginFamily = "core" | "io" | "arch" | "esil" | "lang" | "bin" | "debug" | "anal" | "crypto";

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
	plugin(type: string, maker: any): boolean;
	unload(name: string): boolean;
}

export class Assembler {
	program : string = "";
	labels : any = {};
	endian : boolean = false;
	pc : number = 0;
	r2 : any = null;
	constructor(myr2: R2Pipe | undefined) {
		this.r2 = (typeof myr2 === 'undefined')? r2: myr2;
		this.program = '';
		this.labels = {};
	}
	setProgramCounter(pc: number) {
		this.pc = pc;
	}
	setEndian(big:boolean) {
		this.endian = big;
	}
	toString() {
		return this.program;
	}
	append(x:string) {
		this.pc += x.length / 2;
		this.program += x;
	}
	// api
	label(s:string) : number {
		const pos = this.pc; // this.#program.length / 4;
		this.labels[s] = this.pc;
		return pos;
	}
	asm(s:string) {
		let hex = this.r2.cmd('""pa ' + s).trim();
		if (hex.length < 16) {
			// ok
		} else {
			hex = "____";
			// console.error("Invalid instruction: " + s);
		}
		this.append(hex);
	}
}

export class R2Papi {
	public r2: R2Pipe;

	constructor(r2: R2Pipe) {
		this.r2 = r2;
	}
	getBaseAddress(): NativePointer {
		return new NativePointer(this.cmd("e bin.baddr"));
	}
	jsonToTypescript(name: string, a: any) : string {
		let str = `interface ${name} {\n`;
		if (a.length && a.length > 0) {
			a = a[0];
		}
		for (let k of Object.keys(a)) {
			const typ = typeof (a[k]);
			const nam = k;
			str += `    ${nam}: ${typ};\n`;
		}
		return `${str}}\n`;
	}
	getBits() : string {
		return this.cmd('-b');
	}
	getArch() : string {
		return this.cmd('-a');
	}
	getCpu() : string {
		return this.cmd('-e asm.cpu');
	}
	// TODO: setEndian, setCpu, ...
	setArch(arch: string, bits: number | undefined) {
		this.cmd("-a "+arch);
		if (bits !== undefined) {
			this.cmd("-b "+bits);
		}
	}
	setFlagSpace(name:string) {
		this.cmd('fs ' + name);
	}
	setLogLevel(level: number) : R2Papi {
		this.cmd('e log.level=' + level);
		return this;
	}
	/**
	 * should return the id for the new map using the given file descriptor
	 */
	// rename to createMap or mapFile?
	newMap(fd: number, vaddr: NativePointer, size: number, paddr: NativePointer, perm: Permission, name: string = "") : void {
		this.cmd(`om ${fd} ${vaddr} ${size} ${paddr} ${perm} ${name}`);
	}

	at(a: string) : NativePointer {
		return new NativePointer(a);
	}
	getShell(): R2PapiShell {
		return new R2PapiShell (this);
	}
	// Radare/Frida
	version(): string {
		return this.r2.cmd("?Vq").trim();
	}
	// Process
	platform(): string {
		return this.r2.cmd("uname").trim();
	}
	arch(): string {
		return this.r2.cmd("uname -a").trim();
	}
	bits(): string {
		return this.r2.cmd("uname -b").trim();
	}
	id(): number {
		// getpid();
		return +this.r2.cmd("?vi:$p");
	}
	// Other stuff
	printAt(msg: string, x: number, y: number) : void {
		// see pg, but pg is obrken :D
	}
	clearScreen() : R2Papi {
		this.r2.cmd("!clear");
		return this;
	}
	getConfig(key: string) : Error | string {
		if (key === '') {
			return new Error('Empty key');
		}
		const exist = this.r2.cmd(`e~^${key} =`).trim()
		if (exist === '') {
			return new Error('Config key does not exist');
		}
		return this.r2.call("e " + key).trim();
	}
	setConfig(key: string, val: string) : R2Papi {
		this.r2.call("e " + key + "=" + val);
		return this;
	}
	getRegisterStateForEsil(): string {
		return this.cmdj("dre").trim();
	}
	getRegisters(): any {
		// this.r2.log("winrar" + JSON.stringify(JSON.parse(this.r2.cmd("drj")),null, 2) );
		return this.cmdj("drj");
	}
	resizeFile(newSize: number) : R2Papi {
		this.cmd(`r ${newSize}`);
		return this;
	}
	insertNullBytes(newSize: number, at?: NativePointer|number|string) : R2Papi {
		if (at === undefined) {
			at = "$$";
		}
		this.cmd(`r+${newSize}@${at}`);
		return this;
	}
	removeBytes(newSize: number, at?: NativePointer | number | string) : R2Papi {
		if (at === undefined) {
			at = "$$";
		}
		this.cmd(`r-${newSize}@${at}`);
		return this;
	}
	seek(addr: number) : R2Papi {
		this.cmd(`s ${addr}`);
		return this;
	}
	currentSeek() : NativePointer {
		return new NativePointer('$$');
	}
	seekToRelativeOpcode(nth: number) : NativePointer {
		this.cmd(`so ${nth}`);
		return this.currentSeek();
	}
	getBlockSize() : number {
		return +this.cmd("b");
	}
	setBlockSize(a: number) : R2Papi {
		this.cmd(`b ${a}`);
		return this;
	}
	countFlags() : number {
		return Number(this.cmd("f~?"));
	}
	countFunctions() : number {
		return Number(this.cmd("aflc"));
	}
	analyzeFunctionsWithEsil(depth?: number) {
		this.cmd("aaef");
	}
	analyzeProgramWithEsil(depth?: number) {
		this.cmd("aae");
	}
	analyzeProgram(depth?: number) {
		if (depth === undefined) {
			depth = 0;
		}
		switch (depth) {
		case 0: this.cmd("aa"); break;
		case 1: this.cmd("aaa"); break;
		case 2: this.cmd("aaaa"); break;
		case 3: this.cmd("aaaaa"); break;
		}
		return this;
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
	currentThreadId(): number {
		if (+this.cmd("e cfg.debug")) {
			return +this.cmd("dpt.");
		}
		return this.id();
	}
	setRegisters(obj: any) {
		for (let r of Object.keys(obj)) {
			const v = obj[r];
			this.r2.cmd("dr " + r + "=" + v);
		}
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
	stepUntil(dst: NativePointer | string | number): void {
		this.cmd(`dsu ${dst}`);
	}
	enumerateXrefsTo(s: string) : string[] {
		return this.call("axtq " + s).trim().split(/\n/);
	}
	// TODO: rename to searchXrefsTo ?
	findXrefsTo(s: string, use_esil: boolean) {
		if (use_esil) {
			this.call("/r " + s);
		} else {
			this.call("/re " + s);
		}
	}
	analyzeFunctionsFromCalls() : R2Papi {
		this.call("aac")
		return this;
	}
	analyzeFunctionsWithPreludes() : R2Papi {
		this.call("aap")
		return this;
	}
	analyzeObjCReferences() : R2Papi {
		this.cmd("aao");
		return this;
	}
	analyzeImports() : R2Papi {
		this.cmd("af @ sym.imp.*");
		return this;
	}
	searchDisasm(s: string): SearchResult[] {
		const res: SearchResult[] = this.callj("/ad " + s);
		return res;
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
	// TODO: take a BinFile as argument instead of number
	selectBinary(id: number) : void {
		this.call(`ob ${id}`);
	}
	openFile(name: string): number | Error {
		const ofd = this.call('oqq').trim();
		this.call(`o ${name}`);
		const nfd = this.call('oqq').trim();
		if (ofd === nfd) {
			return new Error('Cannot open file');
		}
		return parseInt(nfd);
	}
	openFileNomap(name: string): number | Error {
		const ofd = this.call('oqq').trim();
		this.call(`of ${name}`);
		const nfd = this.call('oqq').trim();
		if (ofd === nfd) {
			return new Error('Cannot open file');
		}
		return parseInt(nfd);
	}
	currentFile(name: string): string {
		return this.call('o.').trim();
	}
	enumeratePlugins(type: PluginFamily) : any {
		switch (type) {
		case "bin":
			return this.callj("Lij");
		case "io":
			return this.callj("Loj");
		case "core":
			return this.callj("Lcj");
		case "arch":
			return this.callj("LAj");
		case "anal":
			return this.callj("Laj");
		case "lang":
			return this.callj("Llj");
		}
		return []
	}
	enumerateModules() : DebugModule[] {
		return this.callj("dmmj");
	}
	enumerateFiles(): any {
		return this.callj("oj");
	}
	enumerateBinaries(): any {
		return this.callj("obj");
	}
	enumerateMaps(): any {
		return this.callj("omj");
	}
	enumerateClasses() : any {
		return this.callj("icj");
	}
	enumerateSymbols() : any {
		return this.callj("isj");
	}
	enumerateExports() : any {
		return this.callj("iEj");
	}
	enumerateImports() : any {
		return this.callj("iij");
	}
	enumerateLibraries() : string[] {
		return this.callj("ilj");
	}
	enumerateSections() : any {
		return this.callj("iSj");
	}
	enumerateSegments() : any {
		return this.callj("iSSj");
	}
	enumerateEntrypoints() : any {
		return this.callj("iej");
	}
	enumerateRelocations() : any {
		return this.callj("irj");
	}
	enumerateFunctions() : Function[] {
		return this.cmdj("aflj");
	}
	enumerateFlags() : Flag[] {
		return this.cmdj("fj");
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
	setFlag(name: string) {
		this.api.call(`f ${name}=${this.addr}`);
	}
	unsetFlag() {
		this.api.call(`f-${this.addr}`);
	}
	hexdump(length?: number) : string{
		let len = (length === undefined)? "": ""+length;
		return this.api.cmd(`x${len}@${this.addr}`);
	}
	functionGraph(format?: GraphFormat) : string {
		if (format === "dot") {
			return this.api.cmd(`agfd@ ${this.addr}`);
		}
		if (format === "json") {
			return this.api.cmd(`agfj@${this.addr}`);
		}
		if (format === "mermaid") {
			return this.api.cmd(`agfm@${this.addr}`);
		}
		return this.api.cmd(`agf@${this.addr}`);
	}
	readByteArray(len: number) : number[] {
		return JSON.parse(this.api.cmd(`p8j ${len}@${this.addr}`));
	}
	readHexString(len: number) : string {
		return this.api.cmd(`p8 ${len}@${this.addr}`).trim();
	}
	and(a: number): NativePointer {
		const addr = this.api.call(`?v ${this.addr} & ${a}`).trim();
		return new NativePointer(addr);
	}
	or(a: number): NativePointer {
		const addr = this.api.call(`?v ${this.addr} | ${a}`).trim();
		return new NativePointer(addr);
	}
	add(a: number): NativePointer {
		const addr = this.api.call(`?v ${this.addr}+${a}`).trim();
		return new NativePointer(addr);
	}
	sub(a: number): NativePointer {
		const addr = this.api.call(`?v ${this.addr}-${a}`).trim();
		return new NativePointer(addr);
	}
	writeByteArray(data: number[]): NativePointer {
		this.api.cmd("wx " + data.join(""))
		return this;
	}
	writeAssembly(instruction: string) : NativePointer {
		this.api.cmd(`wa ${instruction} @ ${this.addr}`);
		return this;
	}
	writeCString(s: string): NativePointer {
		this.api.call("w " + s);
		return this;
	}
	writeWideString(s: string): NativePointer {
		this.api.call("ww " + s);
		return this;
	}
	asNumber(): number {
		const v = this.api.call("?vi " + this.addr);
		return parseInt(v);
	}
	isNull(): boolean {
		return this.asNumber() == 0
	}
	compare(a : string|number|NativePointer) {
		if (typeof a === "string" || typeof a === "number") {
			a = new NativePointer(a);
		}
		return a.addr === this.addr || (new NativePointer(a.addr)).asNumber() === this.asNumber();
	}
	pointsToNull(): boolean {
		return this.readPointer().compare(0);
	}
	toString() :string {
		return this.addr.trim();
	}
	writePointer(p: NativePointer) : void {
		this.api.cmd(`wvp ${p}@${this}`); // requires 5.8.2
	}
	readPointer() : NativePointer {
		return new NativePointer(this.api.call("pvp@" + this.addr));
	}
	readU8(): number {
		return parseInt(this.api.cmd(`pv1d@${this.addr}`));
	}
	readU16(): number {
		return parseInt(this.api.cmd(`pv2d@${this.addr}`));
	}
	readU16le(): number {
		return parseInt(this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=false`)); // requires 5.8.9
	}
	readU16be(): number {
		return parseInt(this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=true`)); // requires 5.8.9
	}
	readS16(): number {
		return parseInt(this.api.cmd(`pv2d@${this.addr}`)); // requires 5.8.9
	}
	readS16le(): number {
		return parseInt(this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=false`)); // requires 5.8.9
	}
	readS16be(): number {
		return parseInt(this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=true`)); // requires 5.8.9
	}
	readS32(): number { // same as readInt32()
		return parseInt(this.api.cmd(`pv4d@${this.addr}`)); // requires 5.8.9
	}
	readU32(): number {
		return parseInt(this.api.cmd(`pv4u@${this.addr}`)); // requires 5.8.9
	}
	readU32le(): number {
		return parseInt(this.api.cmd(`pv4u@${this.addr}@e:cfg.bigendian=false`)); // requires 5.8.9
	}
	readU32be(): number {
		return parseInt(this.api.cmd(`pv4u@${this.addr}@e:cfg.bigendian=true`)); // requires 5.8.9
	}
	readU64(): number {
		// XXX: use bignum or string here
		return parseInt(this.api.cmd(`pv8u@${this.addr}`));
	}
	readU64le(): number {
		return parseInt(this.api.cmd(`pv8u@${this.addr}@e:cfg.bigendian=false`)); // requires 5.8.9
	}
	readU64be(): number {
		return parseInt(this.api.cmd(`pv8u@${this.addr}@e:cfg.bigendian=true`)); // requires 5.8.9
	}
	writeInt(n:number): boolean {
		return this.writeU32(n);
	}
	writeU8(n: number) : boolean {
		this.api.cmd(`wv1 ${n}@${this.addr}`);
		return true;
	}
	writeU16(n: number) : boolean {
		this.api.cmd(`wv2 ${n}@${this.addr}`);
		return true;
	}
	writeU16be(n: number) : boolean {
		this.api.cmd(`wv2 ${n}@${this.addr}@e:cfg.bigendian=true`);
		return true;
	}
	writeU16le(n: number) : boolean {
		this.api.cmd(`wv2 ${n}@${this.addr}@e:cfg.bigendian=false`);
		return true;
	}
	writeU32(n: number) : boolean {
		this.api.cmd(`wv4 ${n}@${this.addr}`);
		return true;
	}
	writeU32be(n: number) : boolean {
		this.api.cmd(`wv4 ${n}@${this.addr}@e:cfg.bigendian=true`);
		return true;
	}
	writeU32le(n: number) : boolean {
		this.api.cmd(`wv4 ${n}@${this.addr}@e:cfg.bigendian=false`);
		return true;
	}
	writeU64(n: number) : boolean {
		this.api.cmd(`wv8 ${n}@${this.addr}`);
		return true;
	}
	writeU64be(n: number) : boolean {
		this.api.cmd(`wv8 ${n}@${this.addr}@e:cfg.bigendian=true`);
		return true;
	}
	writeU64le(n: number) : boolean {
		this.api.cmd(`wv8 ${n}@${this.addr}@e:cfg.bigendian=false`);
		return true;
	}
	readInt32(): number {
		return this.readU32();
	}
	readCString(): string {
		return JSON.parse(this.api.cmd(`pszj@${this.addr}`)).string;
	}
	readWideString(): string {
		return JSON.parse(this.api.cmd(`pswj@${this.addr}`)).string;
	}
	readPascalString(): string {
		return JSON.parse(this.api.cmd(`pspj@${this.addr}`)).string;
	}
	instruction(): Instruction {
		const op: any = this.api.cmdj(`aoj@${this.addr}`)[0];
		return op;
	}
	disassemble(length?: number) : string {
		let len = (length === undefined)? "": ""+length;
		return this.api.cmd(`pd ${len}@${this.addr}`);
	}
	analyzeFunction() : NativePointer {
		this.api.cmd("af@" + this.addr);
		return this;
	}
	analyzeFunctionRecursively() : NativePointer {
		this.api.cmd("afr@" + this.addr);
		return this;
	}
	name(): string {
		return this.api.cmd("fd " + this.addr).trim();
	}
	methodName(): string {
		// TODO: @ should be optional here, as addr should be passable as argument imho
		return this.api.cmd("ic.@" + this.addr).trim();
	}
	symbolName(): any {
		// TODO: @ should be optional here, as addr should be passable as argument imho
		return this.api.cmd("isj.@" + this.addr).trim();
	}
	getFunction() : Function {
		return this.api.cmdj("afij@"+this.addr);
	}
	basicBlock(): BasicBlock {
		const bb: BasicBlock = this.api.cmdj("abj@" + this.addr);
		return bb;
	}
	functionBasicBlocks(): BasicBlock[] {
		return this.api.cmdj("afbj@"+this.addr);
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

interface base64Interface {
	(message: string, decode?: boolean): string;
}

/*
// already defined by r2
function ptr(x: string|number) {
	return new NativePointer(x);
}
*/

export declare var b64: base64Interface;
export declare var r2: R2Pipe;
export declare var R: R2Papi;
