// main r2papi file

import { R2Shell } from "./shell.js";
import { newAsyncR2PipeFromSync, r2, R2PipeAsync } from "./r2pipe.js";

export type InstructionType =
    | "mov"
    | "jmp"
    | "cmp"
    | "nop"
    | "call"
    | "add"
    | "sub";
export type InstructionFamily = "cpu" | "fpu" | "priv";
export type GraphFormat = "dot" | "json" | "mermaid" | "ascii";
export type Permission = "---" | "r--" | "rw-" | "rwx" | "r-x" | "-wx" | "--x";
export type R2Papi = R2PapiAsync;

export interface SearchResult {
    offset: number; // TODO: rename to addr
    type: string;
    data: string;
}

export interface DebugModule {
    base: string;
    name: string;
    path: string;
    size: number;
}

export interface Flag {
    name: string;
    size: number;
    offset: number;
}

export type PluginFamily =
    | "anal"
    | "arch"
    | "bin"
    | "core"
    | "crypto"
    | "debug"
    | "egg"
    | "esil"
    | "fs"
    | "io"
    | "lang";

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
}

export interface FunctionDetails {
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
}

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
}

export interface Reference {
    from: number;
    type: string;
    perm: string;
    opcode: string;
    fcn_addr: number;
    fcn_name: string;
    realname: string;
    refname: string;
}

export interface BasicBlock {
    addr: number;
    size: number;
    jump: number;
    fail: number;
    opaddr: number;
    inputs: number;
    outputs: number;
    ninstr: number;
    instrs: number[];
    traced: boolean;
}

export class ThreadClass {
    api: any = null;
    constructor(r2: any) {
        this.api = r2;
    }
    async backtrace() {
        return r2.call("dbtj");
    }
    async sleep(seconds: number) {
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
    constructor(r2: R2PipeAsync) {
        this.api = r2;
    }
    fileName(): Promise<string> {
        return this.api.call("dpe").trim();
    }
    name(): string {
        return "Module";
    }
    findBaseAddress() {
        return "TODO";
    }
    getBaseAddress(name: string) {
        return "TODO";
    }
    async getExportByName(name: string) : Promise<NativePointer> {
        const res = await r2.call("iE,name/eq/" + name + ",vaddr/cols,:quiet");
        return ptr(res);
    }
    async findExportByName(name: string): Promise<NativePointer> {
        return this.getExportByName(name);
    }
    async enumerateExports() : Promise<any> {
        // TODO: adjust to be the same output as Frida
        return r2.callj("iEj");
    }
    async enumerateImports() {
        // TODO: adjust to be the same output as Frida
        return r2.callj("iij");
    }
    async enumerateSymbols() : Promise<any> {
        // TODO: adjust to be the same output as Frida
        return r2.callj("isj");
    }
    async enumerateEntrypoints() : Promise<any> {
        // TODO: adjust to be the same output as Frida
        return r2.callj("iej");
    }
    async enumerateRanges() : Promise<any> {
        // TODO: adjust to be the same output as Frida
        return r2.callj("omj");
    }
}

export class ProcessClass {
    r2: any = null;
    constructor(r2: R2PipeAsync) {
        this.r2 = r2;
    }
    enumerateMallocRanges() {}
    enumerateSystemRanges() {}
    enumerateRanges() {}
    enumerateThreads() {
        return r2.callj("dptj");
    }
    async enumerateModules(): Promise<any> {
        await r2.call("cfg.json.num=string"); // to handle 64bit values properly
        if (r2.callj("e cfg.debug")) {
            const modules = r2.callj("dmmj");
            const res = [];
            for (const mod of modules) {
                const entry = {
                    base: new NativePointer(mod.addr),
                    size: new NativePointer(mod.addr_end).sub(mod.addr),
                    path: mod.file,
                    name: mod.name
                };
                res.push(entry);
            }
            return res;
        } else {
            const fname = (x: string) => {
                const y = x.split("/");
                return y[y.length - 1];
            };
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
    getModuleByAddress(addr: NativePointer | number | string): any {}
    getModuleByName(moduleName: string): any {}
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
        if (
            this.r2.callj("e asm.bits") === 64 &&
            this.r2.call("e asm.arch").startsWith("arm")
        ) {
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
    r2: R2PipeAsync;
    constructor(myr2?: R2PipeAsync) {
        if (myr2 === undefined) {
            this.r2 = newAsyncR2PipeFromSync(r2);
        } else {
            this.r2 = myr2;
        }
        this.program = "";
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
    async append(x: string) {
        // append text
        this.pc = await this.pc.add(x.length / 2);
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
    async encode(s: string): Promise<string> {
        const output = await this.r2.call(`pa ${s}`);
        return output.trim();
    }

    /**
     * Decode (disassemble) an instruction by taking the hexpairs string as input.
     * TODO: should take an array of bytes too
     *
     * @param {string} the hexadecimal pairs of bytes to decode as an instruction
     * @returns {string} the mnemonic and operands of the resulting decoding
     */
    async decode(s: string): Promise<string> {
        const output = await this.r2.call(`pad ${s}`);
        return output.trim();
    }
}

/**
 * High level abstraction on top of the r2 command interface provided by r2pipe.
 *
 * @typedef R2Papi
 */
export class R2PapiAsync {
    /**
     * Keep a reference r2pipe instance
     *
     * @type {R2PipeAsync}
     */
    public r2: R2PipeAsync;

    /**
     * Create a new instance of the R2Papi class, taking an r2pipe interface as reference.
     *
     * @param {R2PipeAsync} the r2pipe instance to use as backend.
     * @returns {R2Papi} instance
     */
    constructor(r2: R2PipeAsync) {
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
    async getBaseAddress(): Promise<NativePointer> {
        const v = await this.cmd("e bin.baddr");
        return new NativePointer(v);
    }
    jsonToTypescript(name: string, a: any): string {
        let str = `interface ${name} {\n`;
        if (a.length && a.length > 0) {
            a = a[0];
        }
        for (const k of Object.keys(a)) {
            const typ = typeof a[k];
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
        return +this.cmd("-b");
    }
    /**
     * Get the name of the arch plugin selected, which tends to be the same target architecture.
     * Note that on some situations, this info will be stored protected bby the AirForce.
     * When using the r2ghidra arch plugin the underlying arch is in `asm.cpu`:
     *
     * @returns {string} the name of the target architecture.
     */
    async getArch(): Promise<string> {
        return this.cmdTrim("-a");
    }
    async callTrim(x: string): Promise<string> {
        const res = await this.call(x);
        return res.trim()
    }
    async cmdTrim(x: string): Promise<string> {
        const res = await this.cmd(x);
        return res.trim()
    }
    /**
     * Get the name of the selected CPU for the current selected architecture.
     *
     * @returns {string} the value of asm.cpu
     */
    async getCpu(): Promise<string> {
        // return this.cmd('-c');
        return this.cmdTrim("-e asm.cpu"); // use arch.cpu
    }
    // TODO: setEndian, setCpu, ...
    async setArch(arch: string, bits: number | undefined) {
        await this.cmd("-a " + arch);
        if (bits !== undefined) {
            this.cmd("-b " + bits);
        }
    }

    async setFlagSpace(name: string) {
        await this.cmd("fs " + name);
    }

    async demangleSymbol(lang: string, mangledName: string) : Promise<string> {
        return this.cmdTrim("iD " + lang + " " + mangledName);
    }

    async setLogLevel(level: number) {
        await this.cmd("e log.level=" + level);
    }
    /**
     * should return the id for the new map using the given file descriptor
     */
    // rename to createMap or mapFile?
    newMap(
        fd: number,
        vaddr: NativePointer,
        size: number,
        paddr: NativePointer,
        perm: Permission,
        name: string = ""
    ): void {
        this.cmd(`om ${fd} ${vaddr} ${size} ${paddr} ${perm} ${name}`);
    }

    at(a: string): NativePointer {
        return new NativePointer(a);
    }
    getShell(): R2Shell {
        return new R2Shell(this);
    }
    // Radare/Frida
    async version(): Promise<string> {
        const v = await this.r2.cmd("?Vq");
        return v.trim();
    }
    // Process
    async platform(): Promise<string> {
        const output = await this.r2.cmd("uname");
        return output.trim();
    }
    async arch(): Promise<string> {
        const output = await this.r2.cmd("uname -a");
        return output.trim();
    }
    async bits(): Promise<string> {
        const output = await this.r2.cmd("uname -b");
        return output.trim();
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
    async getConfig(key: string): Promise<Error | string> {
        if (key === "") {
            return new Error("Empty key");
        }
        const exist = await this.r2.cmd(`e~^${key} =`);
        if (exist.trim() === "") {
            return new Error("Config key does not exist");
        }
        const value = await this.r2.call("e " + key);
        return value.trim();
    }
    async setConfig(key: string, val: string): Promise<R2Papi> {
        await this.r2.call("e " + key + "=" + val);
        return this;
    }
    async getRegisterStateForEsil(): Promise<string> {
        const dre = await this.cmdj("dre");
        return this.cmdj("dre");
    }
    async getRegisters(): Promise<any> {
        // this.r2.log("winrar" + JSON.stringify(JSON.parse(this.r2.cmd("drj")),null, 2) );
        return this.cmdj("drj");
    }
    resizeFile(newSize: number): R2Papi {
        this.cmd(`r ${newSize}`);
        return this;
    }
    insertNullBytes(
        newSize: number,
        at?: NativePointer | number | string
    ): R2Papi {
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
        return new NativePointer("$$");
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
            case 0:
                this.cmd("aa");
                break;
            case 1:
                this.cmd("aaa");
                break;
            case 2:
                this.cmd("aaaa");
                break;
            case 3:
                this.cmd("aaaaa");
                break;
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
            selected: true
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
        for (const r of Object.keys(obj)) {
            const v = obj[r];
            this.r2.cmd("dr " + r + "=" + v);
        }
    }
    async hex(s: number | string): Promise<string> {
        const output = await this.r2.cmd("?v " + s);
        return output.trim();
    }
    async step(): Promise<R2Papi> {
        await this.r2.cmd("ds");
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
    async enumerateXrefsTo(s: string): Promise<string[]> {
        const output = await this.call("axtq " + s);
        return output.trim().split(/\n/);
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
        this.call("aac");
        return this;
    }
    autonameAllFunctions(): R2Papi {
        this.call("aan");
        return this;
    }
    analyzeFunctionsWithPreludes(): R2Papi {
        this.call("aap");
        return this;
    }
    analyzeObjCReferences(): R2Papi {
        this.cmd("aao");
        return this;
    }
    async analyzeImports(): Promise<R2Papi> {
        await this.cmd("af @ sym.imp.*");
        return this;
    }
    async searchDisasm(s: string): Promise<SearchResult[]> {
        const res: SearchResult[] = await this.callj("/ad " + s);
        return res;
    }
    async searchString(s: string): Promise<SearchResult[]> {
        const res: SearchResult[] = await this.cmdj("/j " + s);
        return res;
    }
    async searchBytes(data: number[]): Promise<SearchResult[]> {
        function num2hex(data: number): string {
            return (data & 0xff).toString(16);
        }
        const s = data.map(num2hex).join("");
        const res: SearchResult[] = await this.cmdj("/xj " + s);
        return res;
    }
    async binInfo(): Promise<BinFile> {
        try {
            return this.cmdj("ij~{bin}");
        } catch (e: any) {
            return {} as BinFile;
        }
    }
    // TODO: take a BinFile as argument instead of number
    async selectBinary(id: number): Promise<void> {
        await this.call(`ob ${id}`);
    }
    async openFile(name: string): Promise<number | Error> {
        const ofd = await this.call("oqq");
        await this.call(`o ${name}`);
        const nfd = await this.call("oqq");
        if (ofd.trim() === nfd.trim()) {
            return new Error("Cannot open file");
        }
        return parseInt(nfd);
    }
    async openFileNomap(name: string): Promise<number | Error> {
        const ofd = await this.call("oqq");
        await this.call(`of ${name}`);
        const nfd = await this.call("oqq");
        if (ofd.trim() === nfd.trim()) {
            return new Error("Cannot open file");
        }
        return parseInt(nfd);
    }
    async currentFile(name: string): Promise<string> {
        const v = await this.call("o.");
        return v.trim ();
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
        return [];
    }
    async enumerateModules(): Promise<DebugModule[]> {
        return this.callj("dmmj");
    }
    async enumerateFiles(): Promise<any> {
        return this.callj("oj");
    }
    async enumerateBinaries(): Promise<any> {
        return this.callj("obj");
    }
    async enumerateMaps(): Promise<any> {
        return this.callj("omj");
    }
    async enumerateClasses(): Promise<any> {
        return this.callj("icj");
    }
    async enumerateSymbols(): Promise<any> {
        return this.callj("isj");
    }
    async enumerateExports(): Promise<any> {
        return this.callj("iEj");
    }
    async enumerateImports(): Promise<any> {
        return this.callj("iij");
    }
    async enumerateLibraries(): Promise<string[]> {
        return this.callj("ilj");
    }
    async enumerateSections(): Promise<any> {
        return this.callj("iSj");
    }
    async enumerateSegments(): Promise<any> {
        return this.callj("iSSj");
    }
    async enumerateEntrypoints(): Promise<any> {
        return this.callj("iej");
    }
    async enumerateRelocations(): Promise<any> {
        return this.callj("irj");
    }
    async enumerateFunctions(): Promise<FunctionDetails[]> {
        return this.cmdj("aflj");
    }
    async enumerateFlags(): Promise<Flag[]> {
        return this.cmdj("fj");
    }
    skip() {
        this.r2.cmd("dss");
    }
    ptr(s: string | number): NativePointer {
        return new NativePointer(s, this);
    }
    async call(s: string): Promise<string> {
        return this.r2.call(s);
    }
    async callj(s: string): Promise<any> {
        const v = await this.call(s);
        return JSON.parse(v);
    }
    async cmd(s: string): Promise<string> {
        return this.r2.cmd(s);
    }
    async cmdj(s: string): Promise<any> {
        const v = await this.cmd(s);
        return JSON.parse(v);
    }
    async log(s: string) {
        return this.r2.log(s);
    }
    async clippy(msg: string): Promise<void> {
        const v = await this.r2.cmd("?E " + msg);
        this.r2.log(v);
    }
    async ascii(msg: string): Promise<void> {
        const v = await this.r2.cmd("?ea " + msg);
        this.r2.log(v);
    }
}

// useful to call functions via dxc and to define and describe function signatures
export class NativeFunction {
    constructor() {}
}

// uhm not sure how to map this into r2 yet
export class NativeCallback {
    constructor() {}
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

declare global {
    // eslint-disable-next-line no-var
    var R: R2Papi;
    function print (a:string): void;
}
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
        this.api = api?? R;
        this.addr = (s == undefined)? "$$": ("" + s).trim();
    }
    /**
     * Copy N bytes from current pointer to the destination
     *
     * @param {string|NativePointer|number} destination address
     * @param {string|number} amount of bytes
     */
    async copyTo(addr: string|NativePointer|number, size: string|number) : Promise<void> {
        this.api.call(`wf ${this.addr} ${size} @ ${addr}`)
    }
    /**
     * Copy N bytes from given address to the current destination
     *
     * @param {string|NativePointer|number} source address
     * @param {string|number} amount of bytes
     */
    async copyFrom(addr: string|NativePointer|number, size: string|number) : Promise<void> {
        this.api.call(`wf ${addr} ${size} @ ${this.addr}`)
    }
    /**
     * Fill N bytes in this address with zero
     *
     * @param {string|number} amount of bytes
     */
    async zeroFill(size: string|number) : Promise<void> {
        this.api.call(`w0 ${size} @ ${this.addr}`)
    }
    /**
     * Filter a string to be used as a valid flag name
     *
     * @param {string} name of the symbol name
     * @returns {string} filtered name to be used as a flag
     */
    async filterFlag(name: string) : Promise<string> {
        return this.api.call(`fD ${name}`)
    }
    /**
     * Set a flag (name) at the offset pointed
     *
     * @param {string} name of the flag to set
     * @returns {string} base64 decoded string
     */
    async setFlag(name: string) {
        await this.api.call(`f ${name}=${this.addr}`);
    }
    /**
     * Remove the flag in the current offset
     *
     */
    async unsetFlag() {
        await this.api.call(`f-${this.addr}`);
    }
    /**
     * Render an hexadecimal dump of the bytes contained in the range starting
     * in the current pointer and given length.
     *
     * @param {number} length optional amount of bytes to dump, using blocksize
     * @returns {string} string containing the hexadecimal dump of memory
     */
    async hexdump(length?: number): Promise<string> {
        const len = length === undefined ? "" : "" + length;
        return this.api.cmd(`x${len}@${this.addr}`);
    }
    async functionGraph(format?: GraphFormat): Promise<string> {
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
    async readByteArray(len: number): Promise<number[]> {
        const v = await this.api.cmd(`p8j ${len}@${this.addr}`);
        return JSON.parse(v);
    }
    async readHexString(len: number): Promise<string> {
        const v = await this.api.cmd(`p8 ${len}@${this.addr}`);
        return v.trim ();
    }
    async and(a: number): Promise<NativePointer> {
        const addr = await this.api.call(`?v ${this.addr} & ${a}`);
        return new NativePointer(addr.trim());
    }
    async or(a: number): Promise<NativePointer> {
        const addr = await this.api.call(`?v ${this.addr} | ${a}`);
        return new NativePointer(addr.trim());
    }
    async add(a: number): Promise<NativePointer> {
        const addr = await this.api.call(`?v ${this.addr}+${a}`);
        return new NativePointer(addr);
    }
    async sub(a: number): Promise<NativePointer> {
        const addr = await this.api.call(`?v ${this.addr}-${a}`);
        return new NativePointer(addr);
    }
    async writeByteArray(data: number[]): Promise<NativePointer> {
        await this.api.cmd("wx " + data.join(""));
        return this;
    }
    writeAssembly(instruction: string): NativePointer {
        this.api.cmd(`wa ${instruction} @ ${this.addr}`);
        return this;
    }
    async writeCString(s: string): Promise<NativePointer> {
        await this.api.call("w " + s);
        return this;
    }
    async writeWideString(s: string): Promise<NativePointer> {
        await this.api.call("ww " + s);
        return this;
    }
    /**
     * Check if it's a pointer to the address zero. Also known as null pointer.
     *
     * @returns {boolean} true if null
     */
    async isNull(): Promise<boolean> {
        const v = await this.toNumber();
        return v === 0;
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
        const bv: NativePointer =
            typeof a === "string" || typeof a === "number"
                ? new NativePointer(a)
                : a;
        const dist = r2.call(`?vi ${this.addr} - ${bv.addr}`);
        if (dist[0] === "-") {
            return -1;
        }
        if (dist[0] === "0") {
            return 0;
        }
        return 1;
    }
    /**
     * Check if it's a pointer to the address zero. Also known as null pointer.
     *
     * @returns {boolean} true if null
     */
    async pointsToNull(): Promise<boolean> {
        const value = await this.readPointer();
        const v = await value.compare(0);
        return v == 0;
    }
    async toJSON(): Promise<string> {
        const output = await this.api.cmd("?vi " + this.addr.trim());
        return output.trim();
    }
    async toString(): Promise<string> {
        const v = await this.api.cmd("?v " + this.addr.trim());
        return v.trim ();
    }
    async toNumber(): Promise<number> {
        const v = await this.toString();
        return parseInt(v);
    }
    writePointer(p: NativePointer): void {
        this.api.cmd(`wvp ${p}@${this}`); // requires 5.8.2
    }
    async readRelativePointer(): Promise<NativePointer> {
        const v = await this.readS32();
        return this.add(v);
    }
    async readPointer(): Promise<NativePointer> {
        const address = await this.api.call("pvp@" + this.addr);
        return new NativePointer(address);
    }
    async readS8(): Promise<number> {
        // requires 5.8.9
        const v = await this.api.cmd(`pv1d@${this.addr}`);
        return parseInt(v);
    }
    async readU8(): Promise<number> {
        const v = await this.api.cmd(`pv1u@${this.addr}`);
        return parseInt(v);
    }
    async readU16(): Promise<number> {
        const v = await this.api.cmd(`pv2d@${this.addr}`);
        return parseInt(v);
    }
    async readU16le(): Promise<number> {
        const v = await this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=false`);
        return parseInt(v); // requires 5.8.9
    }
    async readU16be(): Promise<number> {
        const v = await this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=true`);
        return parseInt(v); // requires 5.8.9
    }
    async readS16(): Promise<number> {
        const v = await this.api.cmd(`pv2d@${this.addr}`); // requires 5.8.9
        return parseInt(v);
    }
    async readS16le(): Promise<number> {
        const v = await this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=false`);
        return parseInt(v); // requires 5.8.9
    }
    async readS16be(): Promise<number> {
        const v = await this.api.cmd(`pv2d@${this.addr}@e:cfg.bigendian=true`);
        return parseInt(v); // requires 5.8.9
    }
    async readS32(): Promise<number> {
	// requires r2-5.8.9, await statements must be in separate lines
        const v = await this.api.cmd(`pv4d@${this.addr}`);
        return parseInt(v);
    }
    async readU32(): Promise<number> {
        // requires 5.8.9
	const v = await this.api.cmd(`pv4u@${this.addr}`);
        return parseInt(v);
    }
    async readU32le(): Promise<number> {
        const v = await this.api.cmd(`pv4u@${this.addr}@e:cfg.bigendian=false`);
        return parseInt(v); // requires 5.8.9
    }
    async readU32be(): Promise<number> {
        const v = await this.api.cmd(`pv4u@${this.addr}@e:cfg.bigendian=true`)
        return parseInt(v); // requires 5.8.9
    }
    async readU64(): Promise<number> {
        // XXX: use bignum or string here
        const v = await this.api.cmd(`pv8u@${this.addr}`);
        return parseInt(v);
    }
    async readU64le(): Promise<number> {
        const v = await this.api.cmd(`pv8u@${this.addr}@e:cfg.bigendian=false`);
        return parseInt(v); // requires 5.8.9
    }
    async readU64be(): Promise<number> {
        const v = await this.api.cmd(`pv8u@${this.addr}@e:cfg.bigendian=true`)
        return parseInt(v); // requires 5.8.9
    }
    async writeInt(n: number): Promise<boolean> {
        return this.writeU32(n);
    }
    /**
     * Write a byte in the current offset, the value must be between 0 and 255
     *
     * @param {string} n number to write in the pointed byte in the current address
     * @returns {boolean} false if the operation failed
     */
    async writeU8(n: number): Promise<boolean> {
        this.api.cmd(`wv1 ${n}@${this.addr}`);
        return true;
    }
    async writeU16(n: number): Promise<boolean> {
        this.api.cmd(`wv2 ${n}@${this.addr}`);
        return true;
    }
    async writeU16be(n: number): Promise<boolean> {
        this.api.cmd(`wv2 ${n}@${this.addr}@e:cfg.bigendian=true`);
        return true;
    }
    async writeU16le(n: number): Promise<boolean> {
        this.api.cmd(`wv2 ${n}@${this.addr}@e:cfg.bigendian=false`);
        return true;
    }
    async writeU32(n: number): Promise<boolean> {
        await this.api.cmd(`wv4 ${n}@${this.addr}`);
        return true;
    }
    async writeU32be(n: number): Promise<boolean> {
        await this.api.cmd(`wv4 ${n}@${this.addr}@e:cfg.bigendian=true`);
        return true;
    }
    async writeU32le(n: number): Promise<boolean> {
        await this.api.cmd(`wv4 ${n}@${this.addr}@e:cfg.bigendian=false`);
        return true;
    }
    async writeU64(n: number): Promise<boolean> {
        await this.api.cmd(`wv8 ${n}@${this.addr}`);
        return true;
    }
    async writeU64be(n: number): Promise<boolean> {
        await this.api.cmd(`wv8 ${n}@${this.addr}@e:cfg.bigendian=true`);
        return true;
    }
    async writeU64le(n: number): Promise<boolean> {
        await this.api.cmd(`wv8 ${n}@${this.addr}@e:cfg.bigendian=false`);
        return true;
    }
    async readInt32(): Promise<number> {
        return this.readU32();
    }
    async readCString(): Promise<string> {
        const output = await this.api.cmd(`pszj@${this.addr}`);
        return JSON.parse(output).string;
    }
    async readWideString(): Promise<string> {
        const output = await this.api.cmd(`pswj@${this.addr}`);
        return JSON.parse(output).string;
    }
    async readPascalString(): Promise<string> {
        const output = await this.api.cmd(`pspj@${this.addr}`);
        return JSON.parse(output).string;
    }
    async instruction(): Promise<Instruction> {
        const output = await this.api.cmdj(`aoj@${this.addr}`);
        return output[0] as Instruction;
    }
    async disassemble(length?: number): Promise<string> {
        const len = length === undefined ? "" : "" + length;
        return this.api.cmd(`pd ${len}@${this.addr}`);
    }
    async analyzeFunction(): Promise<NativePointer> {
        await this.api.cmd("af@" + this.addr);
        return this;
    }
    async analyzeFunctionRecursively(): Promise<NativePointer> {
        await this.api.cmd("afr@" + this.addr);
        return this;
    }
    async name(): Promise<string> {
        const v = await this.api.cmd("fd " + this.addr);
        return v.trim ();
    }
    async methodName(): Promise<string> {
        // TODO: @ should be optional here, as addr should be passable as argument imho
        const v = await this.api.cmd("ic.@" + this.addr);
        return v.trim ();
    }
    async symbolName(): Promise<string> {
        // TODO: @ should be optional here, as addr should be passable as argument imho
        const name = await this.api.cmd("isj.@" + this.addr);
        return name.trim();
    }
    async getFunction(): Promise<FunctionDetails> {
        return this.api.cmdj("afij@" + this.addr);
    }
    async basicBlock(): Promise<BasicBlock> {
        return this.api.cmdj("abj@" + this.addr);
    }
    async functionBasicBlocks(): Promise<BasicBlock[]> {
        return this.api.cmdj("afbj@" + this.addr);
    }
    async xrefs(): Promise<Reference[]> {
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
export declare const R: R2Papi;

/**
 * Global instance of the Module class based on the current radare2 session.
 * This variable mimics the same APIs shipped by Frida.
 *
 * @type ModuleClass
 */
export declare const Module: ModuleClass;

/**
 * Global instance of the Process class based on the current radare2 session.
 * This variable mimics the same APIs shipped by Frida.
 *
 * @type ProcessClass
 */
export declare const Process: ProcessClass;

/**
 * Global instance of the Thread class based on the current radare2 session.
 * This variable mimics the same APIs shipped by Frida.
 *
 * @type ThreadClass
 */
export declare const Thread: ThreadClass;
