// main r2papi file

import { R2Shell } from "./shell.js";
import { r2, R2Pipe } from "./r2pipe.js";

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

export class ThreadClass {
	api: any = null;
	constructor(r2: any) {
		this.api = r2;
	}
	backtrace() {
		return r2.call("dbtj");
	}
	sleep(seconds: number) {
		return r2.call("sleep " + seconds);
	}
}

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

export class ModuleClass {
	api: any = null;
	constructor(r2: R2Pipe) {
		this.api = r2;
	}
	fileName(): string {
		return this.api.call("dpe").trim()
	}
	name(): string {
		return "Module";
	}
	findBaseAddress() {
		return "TODO";
	}
	findExportByName(name: string): any {
		// TODO
		return "TODO";
	}
	getBaseAddress(name: string) {
		return "TODO";
	}
	getExportByName(name: string) {
		return r2.call("iE,name/eq/" + name + ",vaddr/cols,:quiet").trim();
	}
	enumerateExports() {
		// TODO: use frida json
		return r2.callj("iEj");
	}
	enumerateImports() {
		// TODO: use frida json
		return r2.callj("iij");
	}
	enumerateRanges() {
		// TODO: use frida json
		return r2.callj("isj");
	}
	enumerateSymbols() {
		// TODO: use frida json
		return r2.callj("isj");
	}
}

export class ProcessClass {
	r2: any = null;
	constructor(r2: R2Pipe) {
		this.r2 = r2;
	}
	enumerateMallocRanges() {
	}
	enumerateSystemRanges() {
	}
	enumerateRanges() {
	}
	enumerateThreads() {
		return r2.callj("dptj");
	}
	enumerateModules(): any {
		r2.call("cfg.json.num=string"); // to handle 64bit values properly
		if (r2.callj("e cfg.debug")) {
			const modules = r2.callj("dmmj");
			const res = [];
			for (const mod of modules) {
				const entry = {
					base: new NativePointer(mod.addr),
					size: new NativePointer(mod.addr_end).sub(mod.addr),
					path: mod.file,
					name: mod.name,
				};
				res.push(entry);
			}
			return res;
		} else {
			const fname = (x: string) => {
				const y = x.split("/");
				return y[y.length - 1];
			}
			const bobjs = r2.callj("obj");
			const res = [];
			for (const obj of bobjs) {
				const entry = {
					base: new NativePointer(obj.addr),
					size: obj.size,
					path: obj.file,
					name: fname(obj.file)
				};
				res.push(entry);
			}
			const libs = r2.callj("ilj");
			for (const lib of libs) {
				const entry = {
					base: 0,
					size: 0,
					path: lib,
					name: fname(lib)
				};
				res.push(entry);
			}
			return res;
		}
	}
	getModuleByAddress(addr: NativePointer | number | string): any {
	}
	getModuleByName(moduleName: string): any {
	}
	codeSigningPolicy(): string {
		return "optional";
	}
	getTmpDir() {
		return this.r2.call("e dir.tmp").trim();
	}
	getHomeDir() {
		return this.r2.call("e dir.home").trim();
	}
	platform() {
		return this.r2.call("e asm.os").trim();
	}
	getCurrentDir() {
		return this.r2.call("pwd").trim();
	}
	getCurrentThreadId(): number {
		return +this.r2.call("dpq");
	}
	pageSize(): number {
		if (this.r2.callj("e asm.bits") === 64 && this.r2.call("e asm.arch").startsWith("arm")) {
			return 16384;
		}
		return 4096;
	}
	isDebuggerAttached(): boolean {
		return this.r2.callj("e cfg.debug");
	}
	setExceptionHandler() {
		// do nothing
	}
	id() {
		// 
		return this.r2.callj("dpq").trim();
	}
	pointerSize() {
		return r2.callj("e asm.bits") / 8;
	}
}

/**
 * Assembler and disassembler facilities to decode and encode instructions
 * 
 * @typedef Assembler
 */
export class Assembler {
	program: string = "";
	labels: any = {};
	endian: boolean = false;
	pc: NativePointer = ptr(0);
	r2: R2Pipe;
	constructor(myr2?: R2Pipe) {
		this.r2 = (myr2 === undefined) ? r2 : myr2;
		this.program = '';
		this.labels = {};
	}
	/**
	* Change the address of the program counter, some instructions need to know where
		* are they located before being encoded or decoded.
	*
		* @param {NativePointerValue} 
	  */
	setProgramCounter(pc: NativePointer) {
		this.pc = pc;
	}
	setEndian(big: boolean) {
		this.endian = big;
	}
	toString() {
		return this.program;
	}
	append(x: string) {
		// append text
		this.pc = this.pc.add(x.length / 2);
		this.program += x;
	}
	// api
	label(s: string): NativePointer {
		const pos = this.pc; // this.#program.length / 4;
		this.labels[s] = this.pc;
		return pos;
	}

	/**
	* Encode (assemble) an instruction by taking the string representation.
	*
	* @param {string} the string representation of the instruction to assemble
	* @returns {string} the hexpairs that represent the assembled instruciton
	  */
	encode(s: string): string {
		return this.r2.call(`pa ${s}`).trim();
	}

	/**
	* Decode (disassemble) an instruction by taking the hexpairs string as input.
	* TODO: should take an array of bytes too
	*
	* @param {string} the hexadecimal pairs of bytes to decode as an instruction
	* @returns {string} the mnemonic and operands of the resulting decoding
	  */
	decode(s: string): string {
		return this.r2.call(`pad ${s}`).trim();
	}
}

/**
 * High level abstraction on top of the r2 command interface provided by r2pipe.
 * 
 * @typedef R2Papi
 */
export class R2Papi {
	/**
	 * Keep a reference r2pipe instance
	 *
	 * @type {R2Pipe}
	 */
	public r2: R2Pipe;

	/**
	* Create a new instance of the R2Papi class, taking an r2pipe interface as reference.
	*
		* @param {R2Pipe} the r2pipe instance to use as backend.
		* @returns {R2Papi} instance
	  */
	constructor(r2: R2Pipe) {
		this.r2 = r2;
	}
	toString() {
		return "[object R2Papi]";
	}
	toJSON() {
		return this.toString();
	}
	/**
	 * Get the base address used by the current loaded binary
	 *
	 * @returns {NativePointer} address of the base of the binary
	 */
	getBaseAddress(): NativePointer {
		return new NativePointer(this.cmd("e bin.baddr"));
	}
	jsonToTypescript(name: string, a: any): string {
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
	/**
	* Get the general purpose register size of the targize architecture in bits
	*
	* @returns {number} the regsize
	  */
	getBits(): number {
		return +this.cmd('-b');
	}
	/**
	 * Get the name of the arch plugin selected, which tends to be the same target architecture.
	 * Note that on some situations, this info will be stored protected bby the AirForce.
	 * When using the r2ghidra arch plugin the underlying arch is in `asm.cpu`:
	 *
	 * @returns {string} the name of the target architecture.
	  */
	getArch(): string {
		return this.cmd('-a');
	}
	/**
	 * Get the name of the selected CPU for the current selected architecture.
	 *
	 * @returns {string} the value of asm.cpu
	  */
	getCpu(): string {
		// return this.cmd('-c');
		return this.cmd('-e asm.cpu'); // use arch.cpu
	}
	// TODO: setEndian, setCpu, ...
	setArch(arch: string, bits: number | undefined) {
		this.cmd("-a " + arch);
		if (bits !== undefined) {
			this.cmd("-b " + bits);
		}
	}
	setFlagSpace(name: string) {
		this.cmd('fs ' + name);
	}
	setLogLevel(level: number): R2Papi {
		this.cmd('e log.level=' + level);
		return this;
	}
	/**
	 * should return the id for the new map using the given file descriptor
	 */
	// rename to createMap or mapFile?
	newMap(fd: number, vaddr: NativePointer, size: number, paddr: NativePointer, perm: Permission, name: string = ""): void {
		this.cmd(`om ${fd} ${vaddr} ${size} ${paddr} ${perm} ${name}`);
	}

	at(a: string): NativePointer {
		return new NativePointer(a);
	}
	getShell(): R2Shell {
		return new R2Shell(this);
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
	printAt(msg: string, x: number, y: number): void {
		// see pg, but pg is obrken :D
	}
	clearScreen(): R2Papi {
		this.r2.cmd("!clear");
		return this;
	}
	getConfig(key: string): Error | string {
		if (key === '') {
			return new Error('Empty key');
		}
		const exist = this.r2.cmd(`e~^${key} =`).trim()
		if (exist === '') {
			return new Error('Config key does not exist');
		}
		return this.r2.call("e " + key).trim();
	}
	setConfig(key: string, val: string): R2Papi {
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
	resizeFile(newSize: number): R2Papi {
		this.cmd(`r ${newSize}`);
		return this;
	}
	insertNullBytes(newSize: number, at?: NativePointer | number | string): R2Papi {
		if (at === undefined) {
			at = "$$";
		}
		this.cmd(`r+${newSize}@${at}`);
		return this;
	}
	removeBytes(newSize: number, at?: NativePointer | number | string): R2Papi {
		if (at === undefined) {
			at = "$$";
		}
		this.cmd(`r-${newSize}@${at}`);
		return this;
	}
	seek(addr: number): R2Papi {
		this.cmd(`s ${addr}`);
		return this;
	}
	currentSeek(): NativePointer {
		return new NativePointer('$$');
	}
	seekToRelativeOpcode(nth: number): NativePointer {
		this.cmd(`so ${nth}`);
		return this.currentSeek();
	}
	getBlockSize(): number {
		return +this.cmd("b");
	}
	setBlockSize(a: number): R2Papi {
		this.cmd(`b ${a}`);
		return this;
	}
	countFlags(): number {
		return Number(this.cmd("f~?"));
	}
	countFunctions(): number {
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
	enumerateThreads(): ThreadContext[] {
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
	enumerateXrefsTo(s: string): string[] {
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
	analyzeFunctionsFromCalls(): R2Papi {
		this.call("aac")
		return this;
	}
	autonameAllFunctions(): R2Papi {
		this.call("aan")
		return this;
	}
	analyzeFunctionsWithPreludes(): R2Papi {
		this.call("aap")
		return this;
	}
	analyzeObjCReferences(): R2Papi {
		this.cmd("aao");
		return this;
	}
	analyzeImports(): R2Papi {
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
		function num2hex(data: number): string {
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
	selectBinary(id: number): void {
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
	enumeratePlugins(type: PluginFamily): any {
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
	enumerateModules(): DebugModule[] {
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
	enumerateClasses(): any {
		return this.callj("icj");
	}
	enumerateSymbols(): any {
		return this.callj("isj");
	}
	enumerateExports(): any {
		return this.callj("iEj");
	}
	enumerateImports(): any {
		return this.callj("iij");
	}
	enumerateLibraries(): string[] {
		return this.callj("ilj");
	}
	enumerateSections(): any {
		return this.callj("iSj");
	}
	enumerateSegments(): any {
		return this.callj("iSSj");
	}
	enumerateEntrypoints(): any {
		return this.callj("iej");
	}
	enumerateRelocations(): any {
		return this.callj("irj");
	}
	enumerateFunctions(): Function[] {
		return this.cmdj("aflj");
	}
	enumerateFlags(): Flag[] {
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

// useful to call functions via dxc and to define and describe function signatures
export class NativeFunction {
	constructor() {
	}
}

// uhm not sure how to map this into r2 yet
export class NativeCallback {
	constructor() {
	}
}

// export const NULL = ptr("0");yet

/**
 * Global function that returns a new instance of a NativePointer.
 * Saves some typing: `ptr(0)` is the same as `new NativePointer(0)`
 * 
 * @type function
 */
export declare function ptr(v: NativePointerValue): NativePointer;

/**
 * A NativePointer can be described using a string that contains a number in any base (hexadecimal and decimal are the most common formats used)
 * But it actually supports anything else that could be handled by radare2. You can use symbol names, math operations or special symbols like `$$`.
 * 
 * @type NativePointerValue
 */
export type NativePointerValue = string | number | NativePointer;

/**
 * Class providing a way to work with 64bit pointers from Javascript, this API mimics the same
 * well-known promitive available in Frida, but it's baked by the current session of r2.
 * 
 * It is also possible to use this class via the global `ptr` function.
 * 
 * @typedef NativePointer
 */
export class NativePointer {
	addr: string;

	api: R2Papi;
	constructor(s: NativePointerValue, api?: R2Papi) {
		if (api === undefined) {
			this.api = R;
		} else {
			this.api = api;
		}
		// this.api.r2.log("NP " + s);
		this.addr = ("" + s).trim();
	}
	/**
	 * Set a flag (name) at the offset pointed
	 *
	 * @param {string} name name of the flag to set
	 * @returns {string} base64 decoded string
	 */
	setFlag(name: string) {
		this.api.call(`f ${name}=${this.addr}`);
	}
	/**
	 * Remove the flag in the current offset
	 *
	 */
	unsetFlag() {
		this.api.call(`f-${this.addr}`);
	}
	/**
	 * Render an hexadecimal dump of the bytes contained in the range starting
	 * in the current pointer and given length.
	 *
	 * @param {number} length optional amount of bytes to dump, using blocksize
	 * @returns {string} string containing the hexadecimal dump of memory
	 */
	hexdump(length?: number): string {
		let len = (length === undefined) ? "" : "" + length;
		return this.api.cmd(`x${len}@${this.addr}`);
	}
	functionGraph(format?: GraphFormat): string {
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
	readByteArray(len: number): number[] {
		return JSON.parse(this.api.cmd(`p8j ${len}@${this.addr}`));
	}
	readHexString(len: number): string {
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
	writeAssembly(instruction: string): NativePointer {
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
	/**
		 * Check if it's a pointer to the address zero. Also known as null pointer.
		 *
		 * @returns {boolean} true if null
		 */
	isNull(): boolean {
		return this.toNumber() == 0
	}
	/**
		 * Compare current pointer with the passed one, and return -1, 0 or 1.
		 *
		 * * if (this < arg) return -1;
		 * * if (this > arg) return 1;
		 * * if (this == arg) return 0;
		 *
		 * @returns {number} returns -1, 0 or 1 depending on the comparison of the pointers
		 */
	compare(a: NativePointerValue): number {
		const bv: NativePointer = (typeof a === "string" || typeof a === "number")
			? new NativePointer(a) : a;
		const dist = r2.call(`?vi ${this.addr} - ${bv.addr}`);
		if (dist[0] === '-') {
			return -1;
		}
		if (dist[0] === '0') {
			return 0;
		}
		return 1;
	}
	/**
		 * Check if it's a pointer to the address zero. Also known as null pointer.
		 *
		 * @returns {boolean} true if null
		 */
	pointsToNull(): boolean {
		return this.readPointer().compare(0) == 0;
	}
	toJSON(): string {
		return this.api.cmd('?vi ' + this.addr.trim()).trim();
	}
	toString(): string {
		return this.api.cmd('?v ' + this.addr.trim()).trim();
	}
	toNumber(): number {
		return parseInt(this.toString());
	}
	writePointer(p: NativePointer): void {
		this.api.cmd(`wvp ${p}@${this}`); // requires 5.8.2
	}
	readRelativePointer(): NativePointer {
		return this.add(this.readS32());
	}
	readPointer(): NativePointer {
		return new NativePointer(this.api.call("pvp@" + this.addr));
	}
	readS8(): number { // requires 5.8.9
		return parseInt(this.api.cmd(`pv1d@${this.addr}`));
	}
	readU8(): number {
		return parseInt(this.api.cmd(`pv1u@${this.addr}`));
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
	writeInt(n: number): boolean {
		return this.writeU32(n);
	}
	/**
	 * Write a byte in the current offset, the value must be between 0 and 255
	 *
	 * @param {string} n number to write in the pointed byte in the current address
	 * @returns {boolean} false if the operation failed
	 */
	writeU8(n: number): boolean {
		this.api.cmd(`wv1 ${n}@${this.addr}`);
		return true;
	}
	writeU16(n: number): boolean {
		this.api.cmd(`wv2 ${n}@${this.addr}`);
		return true;
	}
	writeU16be(n: number): boolean {
		this.api.cmd(`wv2 ${n}@${this.addr}@e:cfg.bigendian=true`);
		return true;
	}
	writeU16le(n: number): boolean {
		this.api.cmd(`wv2 ${n}@${this.addr}@e:cfg.bigendian=false`);
		return true;
	}
	writeU32(n: number): boolean {
		this.api.cmd(`wv4 ${n}@${this.addr}`);
		return true;
	}
	writeU32be(n: number): boolean {
		this.api.cmd(`wv4 ${n}@${this.addr}@e:cfg.bigendian=true`);
		return true;
	}
	writeU32le(n: number): boolean {
		this.api.cmd(`wv4 ${n}@${this.addr}@e:cfg.bigendian=false`);
		return true;
	}
	writeU64(n: number): boolean {
		this.api.cmd(`wv8 ${n}@${this.addr}`);
		return true;
	}
	writeU64be(n: number): boolean {
		this.api.cmd(`wv8 ${n}@${this.addr}@e:cfg.bigendian=true`);
		return true;
	}
	writeU64le(n: number): boolean {
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
	disassemble(length?: number): string {
		let len = (length === undefined) ? "" : "" + length;
		return this.api.cmd(`pd ${len}@${this.addr}`);
	}
	analyzeFunction(): NativePointer {
		this.api.cmd("af@" + this.addr);
		return this;
	}
	analyzeFunctionRecursively(): NativePointer {
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
	getFunction(): Function {
		return this.api.cmdj("afij@" + this.addr);
	}
	basicBlock(): BasicBlock {
		const bb: BasicBlock = this.api.cmdj("abj@" + this.addr);
		return bb;
	}
	functionBasicBlocks(): BasicBlock[] {
		return this.api.cmdj("afbj@" + this.addr);
	}
	xrefs(): Reference[] {
		return this.api.cmdj("axtj@" + this.addr);
	}
}

/*
// already defined by r2
function ptr(x: string|number) {
	return new NativePointer(x);
}
*/

/**
 * Global instance of R2Papi based on the current session of radare2.
 * Note that `r2` is the global instance of `r2pipe` used by `R`.
 * 
 * @type R2Papi
 */
export declare var R: R2Papi;

/**
 * Global instance of the Module class based on the current radare2 session.
 * This variable mimics the same APIs shipped by Frida.
 * 
 * @type ModuleClass
 */
export declare var Module: ModuleClass;

/**
 * Global instance of the Process class based on the current radare2 session.
 * This variable mimics the same APIs shipped by Frida.
 * 
 * @type ProcessClass
 */
export declare var Process: ProcessClass;

/**
 * Global instance of the Thread class based on the current radare2 session.
 * This variable mimics the same APIs shipped by Frida.
 * 
 * @type ThreadClass
 */
export declare var Thread: ThreadClass;
