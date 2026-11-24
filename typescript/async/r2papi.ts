// main r2papi file

import { R2Shell } from "./shell.js";
import { newAsyncR2PipeFromSync, r2, R2PipeAsync } from "./r2pipe.js";
import type {
    BinObject,
    BinPluginsOutput,
    DebugThread,
    ClassInfo,
    Entrypoint,
    ImportSymbol,
    MapEntry,
    OpenedFile,
    PluginInfo,
    RegisterDump,
    Relocation,
    Section,
    Segment,
    SymbolInfo
} from "./outputs.js";

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
    addr: number;
    type: string;
    data: string;
}

export interface DebugModule {
    /** base address as a hex string (e.g. "0x100000000") */
    base: string;
    name: string;
    path: string;
    size: number;
}

export interface Flag {
    name: string;
    size: number;
    addr: number;
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
    addr: number;
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

export interface BacktraceFrame {
    addr: number;
    sp?: number;
    bp?: number;
    [key: string]: unknown;
}

export class ThreadClass {
    api: R2PipeAsync;
    constructor(r2: R2PipeAsync) {
        this.api = r2;
    }
    async backtrace(): Promise<BacktraceFrame[]> {
        return this.api.callj("dbtj");
    }
    async sleep(seconds: number): Promise<void> {
        await this.api.call("sleep " + seconds);
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

async function loadModules(api: R2PipeAsync): Promise<DebugModule[]> {
    // json.num=string makes 64-bit addresses survive as strings instead of
    // being truncated to doubles; restore the user setting afterwards.
    const prev = (await api.call("e cfg.json.num")).trim();
    await api.call("e cfg.json.num=string");
    try {
        const isDebug = (await api.call("e cfg.debug")).trim() === "true";
        if (isDebug) {
            const mods: any[] = (await api.callj("dmmj")) || [];
            return mods.map((mod) => {
                const base = mod.base ?? mod.addr ?? mod.baddr ?? "0";
                const size =
                    mod.size !== undefined
                        ? parseAddr(mod.size)
                        : mod.addr_end !== undefined
                          ? parseAddr(mod.addr_end) - parseAddr(base)
                          : 0;
                const file = mod.file ?? mod.path ?? mod.name ?? "";
                return {
                    base: String(base),
                    size,
                    path: String(file),
                    name: String(mod.name ?? basename(String(file)))
                };
            });
        }
        const fname = (x: string) => {
            const y = String(x).split("/");
            return y[y.length - 1];
        };
        const res: DebugModule[] = [];
        const bobjs: BinObject[] = (await api.callj("obj")) || [];
        for (const obj of bobjs) {
            res.push({
                base: "0x" + Number(obj.addr).toString(16),
                size: Number(obj.size) || 0,
                path: obj.name,
                name: fname(obj.name)
            });
        }
        const libs: string[] = (await api.callj("ilj")) || [];
        for (const lib of libs) {
            res.push({ base: "0x0", size: 0, path: lib, name: fname(lib) });
        }
        return res;
    } finally {
        await api.call("e cfg.json.num=" + (prev || "number"));
    }
}

function parseAddr(v: unknown): number {
    if (typeof v === "number") {
        return v;
    }
    const s = String(v).trim();
    if (s.startsWith("0x") || s.startsWith("0X")) {
        return parseInt(s, 16);
    }
    const n = Number(s);
    return Number.isFinite(n) ? n : 0;
}

function basename(p: string): string {
    const y = p.split("/");
    return y[y.length - 1] || p;
}

function toBigAddr(v: NativePointerValue): bigint {
    if (v instanceof NativePointer) {
        // NativePointer.addr may be a hex string expression like "$$+0x10";
        // only plain addresses can be compared numerically.
        const s = v.addr.trim();
        return s.startsWith("0x") || /^\d+$/.test(s) ? BigInt(s) : 0n;
    }
    if (typeof v === "bigint") {
        return v;
    }
    if (typeof v === "number") {
        return BigInt(Math.trunc(v));
    }
    const s = String(v).trim();
    try {
        return BigInt(s);
    } catch (e) {
        return BigInt(parseAddr(s));
    }
}

export class ModuleClass {
    api: R2PipeAsync;
    constructor(r2: R2PipeAsync) {
        this.api = r2;
    }
    /** Path of the backing file of the current debuggee or binary. */
    async fileName(): Promise<string> {
        const debug = (await this.api.call("dpe")).trim();
        if (debug) {
            return debug;
        }
        return (await this.api.call("o.")).trim();
    }
    async name(): Promise<string> {
        return basename(await this.fileName());
    }
    /** Base address of the main binary loaded in the session. */
    async findBaseAddress(): Promise<NativePointer> {
        return this.getBaseAddress();
    }
    /**
     * Base address of a module. When `name` is omitted the main (first)
     * module is returned.
     */
    async getBaseAddress(name?: string): Promise<NativePointer> {
        const mods = await loadModules(this.api);
        const mod = name
            ? mods.find(
                  (m) =>
                      m.name === name ||
                      m.path === name ||
                      m.path.endsWith("/" + name)
              )
            : mods[0];
        if (!mod) {
            throw new Error("Module not found: " + name);
        }
        return new NativePointer(mod.base);
    }
    async getExportByName(name: string): Promise<NativePointer> {
        const hit = (await this.enumerateExports()).find((e) => e.name === name);
        if (!hit) {
            throw new Error("Export not found: " + name);
        }
        return new NativePointer("0x" + Number(hit.vaddr).toString(16));
    }
    async findExportByName(name: string): Promise<NativePointer> {
        return this.getExportByName(name);
    }
    async enumerateExports(): Promise<SymbolInfo[]> {
        return this.api.callj("iEj");
    }
    async enumerateImports(): Promise<ImportSymbol[]> {
        return this.api.callj("iij");
    }
    async enumerateSymbols(): Promise<SymbolInfo[]> {
        return this.api.callj("isj");
    }
    async enumerateEntrypoints(): Promise<Entrypoint[]> {
        return this.api.callj("iej");
    }
    async enumerateRanges(): Promise<MapEntry[]> {
        return this.api.callj("omj");
    }
}

export class ProcessClass {
    r2: R2PipeAsync;
    constructor(r2: R2PipeAsync) {
        this.r2 = r2;
    }
    /** Ranges backed by malloc */
    async enumerateMallocRanges(): Promise<MapEntry[]> {
        const maps = await this.enumerateRanges();
        return maps.filter((m) => (m.name || "").includes("malloc"));
    }
    /**
     * Ranges that do not belong to the main heap. r2 has no direct notion
     * of "system ranges", so this returns every map that is not a malloc
     * range. Refine in your script if you need narrower semantics.
     */
    async enumerateSystemRanges(): Promise<MapEntry[]> {
        const maps = await this.enumerateRanges();
        return maps.filter((m) => !(m.name || "").includes("malloc"));
    }
    async enumerateRanges(): Promise<MapEntry[]> {
        return this.r2.callj("omj");
    }
    async enumerateThreads(): Promise<DebugThread[]> {
        return this.r2.callj("dptj");
    }
    async enumerateModules(): Promise<DebugModule[]> {
        return loadModules(this.r2);
    }
    async getModuleByAddress(
        addr: NativePointer | number | string
    ): Promise<DebugModule | null> {
        const needle = toBigAddr(addr);
        const mods = await this.enumerateModules();
        for (const mod of mods) {
            const base = BigInt(parseAddr(mod.base));
            const size = BigInt(Math.trunc(mod.size) || 0);
            if (needle >= base && (size === 0n || needle < base + size)) {
                return mod;
            }
        }
        return null;
    }
    async getModuleByName(moduleName: string): Promise<DebugModule | null> {
        const mods = await this.enumerateModules();
        return (
            mods.find(
                (m) =>
                    m.name === moduleName ||
                    m.path === moduleName ||
                    m.path.endsWith("/" + moduleName)
            ) ?? null
        );
    }
    codeSigningPolicy(): string {
        // r2 does not expose the code signing policy of the debuggee; the
        // value is kept for frida compatibility.
        return "optional";
    }
    async getTmpDir(): Promise<string> {
        return (await this.r2.call("e dir.tmp")).trim();
    }
    async getHomeDir(): Promise<string> {
        return (await this.r2.call("e dir.home")).trim();
    }
    async platform(): Promise<string> {
        return (await this.r2.call("e asm.os")).trim();
    }
    async getCurrentDir(): Promise<string> {
        return (await this.r2.call("pwd")).trim();
    }
    async getCurrentThreadId(): Promise<number> {
        const dbg = (await this.r2.call("e cfg.debug")).trim() === "true";
        if (!dbg) {
            return this.id();
        }
        return parseInt((await this.r2.call("dpt.")).trim(), 10);
    }
    async pageSize(): Promise<number> {
        const bits = parseInt((await this.r2.call("e asm.bits")).trim(), 10);
        const arch = (await this.r2.call("e asm.arch")).trim();
        if (bits === 64 && arch.startsWith("arm")) {
            return 16384;
        }
        return 4096;
    }
    async isDebuggerAttached(): Promise<boolean> {
        return (await this.r2.call("e cfg.debug")).trim() === "true";
    }
    setExceptionHandler() {
        // r2 does not expose Mach exception ports to scripts; kept as a
        // no-op for frida compatibility.
    }
    /** Pid of the debuggee when debugging, -1 otherwise. */
    async id(): Promise<number> {
        const dbg = (await this.r2.call("e cfg.debug")).trim() === "true";
        if (!dbg) {
            return -1;
        }
        return parseInt((await this.r2.call("dpq")).trim(), 10);
    }
    async pointerSize(): Promise<number> {
        return parseInt((await this.r2.call("e asm.bits")).trim(), 10) / 8;
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
        return new NativePointer(v, this);
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
    async getBits(): Promise<number> {
        return parseAddr((await this.cmd("e asm.bits")).trim());
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
            await this.cmd("-b " + bits);
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
    async newMap(
        fd: number,
        vaddr: NativePointer,
        size: number,
        paddr: NativePointer,
        perm: Permission,
        name: string = ""
    ): Promise<void> {
        await this.cmd(`om ${fd} ${vaddr} ${size} ${paddr} ${perm} ${name}`);
    }

    at(a: NativePointerValue): NativePointer {
        return new NativePointer(a, this);
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
    /**
     * Pid of the debuggee when debugging, or -1 when not debugging.
     */
    async id(): Promise<number> {
        const dbg = (await this.r2.call("e cfg.debug")).trim() === "true";
        if (!dbg) {
            return -1;
        }
        return parseInt((await this.r2.call("dpq")).trim(), 10);
    }
    // Other stuff
    printAt(msg: string, x: number, y: number): void {
        // see pg, but pg is obrken :D
    }
    async clearScreen(): Promise<R2Papi> {
        await this.r2.cmd("!clear");
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
        return this.cmd("dre");
    }
    async getRegisters(): Promise<RegisterDump> {
        return this.cmdj("drj");
    }
    async resizeFile(newSize: number): Promise<R2Papi> {
        await this.cmd(`r ${newSize}`);
        return this;
    }
    async insertNullBytes(
        newSize: number,
        at?: NativePointer | number | string
    ): Promise<R2Papi> {
        if (at === undefined) {
            at = "$$";
        }
        await this.cmd(`r+${newSize}@${at}`);
        return this;
    }
    async removeBytes(newSize: number, at?: NativePointer | number | string): Promise<R2Papi> {
        if (at === undefined) {
            at = "$$";
        }
        await this.cmd(`r-${newSize}@${at}`);
        return this;
    }
    async seek(addr: number | string | NativePointer): Promise<R2Papi> {
        await this.cmd(`s ${addr}`);
        return this;
    }
    currentSeek(): NativePointer {
        return new NativePointer("$$", this);
    }
    async seekToRelativeOpcode(nth: number): Promise<NativePointer> {
        await this.cmd(`so ${nth}`);
        return this.currentSeek();
    }
    async getBlockSize(): Promise<number> {
        return parseAddr((await this.cmd("b")).trim());
    }
    async setBlockSize(a: number): Promise<R2Papi> {
        await this.cmd(`b ${a}`);
        return this;
    }
    async countFlags(): Promise<number> {
        return Number((await this.cmd("f~?")).trim());
    }
    async countFunctions(): Promise<number> {
        return Number((await this.cmd("aflc")).trim());
    }
    async analyzeFunctionsWithEsil(_depth?: number): Promise<R2Papi> {
        await this.cmd("aaef");
        return this;
    }
    async analyzeProgramWithEsil(_depth?: number): Promise<R2Papi> {
        await this.cmd("aae");
        return this;
    }
    async analyzeProgram(depth?: number): Promise<R2Papi> {
        if (depth === undefined) {
            depth = 0;
        }
        switch (depth) {
            case 0:
                await this.cmd("aa");
                break;
            case 1:
                await this.cmd("aaa");
                break;
            case 2:
                await this.cmd("aaaa");
                break;
            case 3:
                await this.cmd("aaaaa");
                break;
        }
        return this;
    }
    async enumerateThreads(): Promise<ThreadContext[]> {
        // dptj is only available when debugging; fall back to a single
        // pseudo-thread holding the current register state otherwise.
        const dbg = (await this.cmd("e cfg.debug")).trim() === "true";
        if (dbg) {
            const threads: DebugThread[] = (await this.cmdj("dptj")) || [];
            return threads.map((t) => ({
                context: null,
                id: typeof t.pid === "number" ? t.pid : 0,
                state: String(t.status ?? "unknown"),
                selected: !!t.current
            }));
        }
        const regs0 = await this.cmdj("drj");
        return [
            {
                context: regs0,
                id: 0,
                state: "running",
                selected: true
            }
        ];
    }
    async currentThreadId(): Promise<number> {
        if ((await this.cmd("e cfg.debug")).trim() === "true") {
            return parseInt((await this.cmd("dpt.")).trim(), 10);
        }
        return this.id();
    }
    async setRegisters(obj: Record<string, number | string>): Promise<void> {
        for (const r of Object.keys(obj)) {
            const v = obj[r];
            await this.r2.cmd("dr " + r + "=" + v);
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
    async stepOver(): Promise<R2Papi> {
        await this.r2.cmd("dso");
        return this;
    }
    async math(expr: number | string): Promise<number> {
        return parseAddr((await this.r2.cmd("?v " + expr)).trim());
    }
    async stepUntil(dst: NativePointer | string | number): Promise<void> {
        await this.cmd(`dsu ${dst}`);
    }
    async enumerateXrefsTo(s: string): Promise<string[]> {
        const output = await this.call("axtq " + s);
        return output.trim().split(/\n/);
    }
    // TODO: rename to searchXrefsTo ?
    async findXrefsTo(s: string, use_esil: boolean): Promise<void> {
        if (use_esil) {
            await this.call("/r " + s);
        } else {
            await this.call("/re " + s);
        }
    }
    async analyzeFunctionsFromCalls(): Promise<R2Papi> {
        await this.call("aac");
        return this;
    }
    async autonameAllFunctions(): Promise<R2Papi> {
        await this.call("aan");
        return this;
    }
    async analyzeFunctionsWithPreludes(): Promise<R2Papi> {
        await this.call("aap");
        return this;
    }
    async analyzeObjCReferences(): Promise<R2Papi> {
        await this.cmd("aao");
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
        const num2hex = (data: number): string =>
            (data & 0xff).toString(16).padStart(2, "0");
        const s = data.map(num2hex).join("");
        const res: SearchResult[] = await this.cmdj("/xj " + s);
        return res;
    }
    async binInfo(): Promise<BinFile> {
        try {
            const v = await this.cmdj("ij");
            return (v && v.bin ? v.bin : {}) as BinFile;
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
        return parseInt(nfd.trim(), 10);
    }
    async openFileNomap(name: string): Promise<number | Error> {
        const ofd = await this.call("oqq");
        await this.call(`of ${name}`);
        const nfd = await this.call("oqq");
        if (ofd.trim() === nfd.trim()) {
            return new Error("Cannot open file");
        }
        return parseInt(nfd.trim(), 10);
    }
    async currentFile(_name: string): Promise<string> {
        const v = await this.call("o.");
        return v.trim ();
    }
    async enumeratePlugins(type: PluginFamily): Promise<PluginInfo[]> {
        switch (type) {
            case "bin": {
                // Lij returns {"bin": [...]} instead of a bare array
                const out: BinPluginsOutput = await this.callj("Lij");
                return (out && out.bin) || [];
            }
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
        return loadModules(this.r2);
    }
    async enumerateFiles(): Promise<OpenedFile[]> {
        return this.callj("oj");
    }
    async enumerateBinaries(): Promise<BinObject[]> {
        return this.callj("obj");
    }
    async enumerateMaps(): Promise<MapEntry[]> {
        return this.callj("omj");
    }
    async enumerateClasses(): Promise<ClassInfo[]> {
        return this.callj("icj");
    }
    async enumerateSymbols(): Promise<SymbolInfo[]> {
        return this.callj("isj");
    }
    async enumerateExports(): Promise<SymbolInfo[]> {
        return this.callj("iEj");
    }
    async enumerateImports(): Promise<ImportSymbol[]> {
        return this.callj("iij");
    }
    async enumerateLibraries(): Promise<string[]> {
        return this.callj("ilj");
    }
    async enumerateSections(): Promise<Section[]> {
        return this.callj("iSj");
    }
    async enumerateSegments(): Promise<Segment[]> {
        return this.callj("iSSj");
    }
    async enumerateEntrypoints(): Promise<Entrypoint[]> {
        return this.callj("iej");
    }
    async enumerateRelocations(): Promise<Relocation[]> {
        return this.callj("irj");
    }
    async enumerateFunctions(): Promise<FunctionDetails[]> {
        return this.cmdj("aflj");
    }
    async enumerateFlags(): Promise<Flag[]> {
        return this.cmdj("fj");
    }
    async skip(): Promise<void> {
        await this.r2.cmd("dss");
    }
    ptr(s: NativePointerValue): NativePointer {
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
export type NativePointerValue = string | number | bigint | NativePointer;

function clampByte(n: number): number {
    return n & 0xff;
}

function byteToHex(n: number): string {
    return clampByte(n).toString(16).padStart(2, "0");
}

function byteArrayToHex(data: ArrayLike<number>): string {
    let hex = "";
    for (let i = 0; i < data.length; i++) {
        hex += byteToHex(data[i]);
    }
    return hex;
}

function normalizeHexString(hex: string): string {
    const normalized = hex.replace(/0x/gi, "").replace(/\s+/g, "");
    if (normalized.length % 2 !== 0) {
        throw new Error("Hex string must contain an even number of digits");
    }
    return normalized.toLowerCase();
}

function bytesToUnsignedBigInt(bytes: number[], littleEndian: boolean): bigint {
    const ordered = littleEndian ? [...bytes].reverse() : bytes;
    let value = 0n;
    for (const byte of ordered) {
        value = (value << 8n) | BigInt(clampByte(byte));
    }
    return value;
}

function bytesToSignedBigInt(bytes: number[], littleEndian: boolean): bigint {
    const unsigned = bytesToUnsignedBigInt(bytes, littleEndian);
    const bits = BigInt(bytes.length * 8);
    const signBit = 1n << (bits - 1n);
    if ((unsigned & signBit) !== 0n) {
        return unsigned - (1n << bits);
    }
    return unsigned;
}

function unsignedBigIntToBytes(
    value: bigint,
    byteLength: number,
    littleEndian: boolean
): number[] {
    const bits = BigInt(byteLength * 8);
    const max = 1n << bits;
    if (value < 0n || value >= max) {
        throw new RangeError(`Value ${value} does not fit in ${byteLength * 8} bits`);
    }
    const bytes = new Array<number>(byteLength).fill(0);
    let current = value;
    for (let i = byteLength - 1; i >= 0; i--) {
        bytes[i] = Number(current & 0xffn);
        current >>= 8n;
    }
    return littleEndian ? bytes.reverse() : bytes;
}

function signedBigIntToBytes(
    value: bigint,
    byteLength: number,
    littleEndian: boolean
): number[] {
    const bits = BigInt(byteLength * 8);
    const min = -(1n << (bits - 1n));
    const max = (1n << (bits - 1n)) - 1n;
    if (value < min || value > max) {
        throw new RangeError(`Value ${value} does not fit in ${byteLength * 8} signed bits`);
    }
    const normalized = value < 0n ? value + (1n << bits) : value;
    return unsignedBigIntToBytes(normalized, byteLength, littleEndian);
}

function parseInteger(value: number | string | bigint): bigint {
    if (typeof value === "bigint") {
        return value;
    }
    if (typeof value === "number") {
        if (!Number.isFinite(value) || !Number.isInteger(value)) {
            throw new TypeError("Expected an integer number");
        }
        return BigInt(value);
    }
    const trimmed = value.trim();
    if (trimmed === "") {
        throw new TypeError("Expected a non-empty integer string");
    }
    return BigInt(trimmed);
}

function bigintToSafeNumber(value: bigint, methodName: string): number {
    const numberValue = Number(value);
    if (!Number.isSafeInteger(numberValue)) {
        throw new RangeError(
            `${methodName} exceeds Number.MAX_SAFE_INTEGER; use a bigint or string helper instead`
        );
    }
    return numberValue;
}

function encodeUtf8String(text: string, zeroTerminated: boolean): number[] {
    const encoded = encodeURIComponent(text);
    const bytes: number[] = [];
    for (let i = 0; i < encoded.length; i++) {
        const ch = encoded[i];
        if (ch === "%") {
            bytes.push(parseInt(encoded.slice(i + 1, i + 3), 16));
            i += 2;
        } else {
            bytes.push(ch.charCodeAt(0));
        }
    }
    if (zeroTerminated) {
        bytes.push(0);
    }
    return bytes;
}

function decodeUtf8Bytes(bytes: number[]): string {
    let encoded = "";
    for (const byte of bytes) {
        encoded += "%" + byteToHex(byte);
    }
    try {
        return decodeURIComponent(encoded);
    } catch (e: any) {
        let text = "";
        for (const byte of bytes) {
            text += String.fromCharCode(clampByte(byte));
        }
        return text;
    }
}

function encodeUtf16String(
    text: string,
    littleEndian: boolean,
    zeroTerminated: boolean
): number[] {
    const bytes: number[] = [];
    for (let i = 0; i < text.length; i++) {
        const code = text.charCodeAt(i);
        const hi = (code >> 8) & 0xff;
        const lo = code & 0xff;
        if (littleEndian) {
            bytes.push(lo, hi);
        } else {
            bytes.push(hi, lo);
        }
    }
    if (zeroTerminated) {
        bytes.push(0, 0);
    }
    return bytes;
}

function decodeUtf16Bytes(bytes: number[], littleEndian: boolean): string {
    const evenLength = bytes.length - (bytes.length % 2);
    let text = "";
    for (let i = 0; i < evenLength; i += 2) {
        const code = littleEndian
            ? clampByte(bytes[i]) | (clampByte(bytes[i + 1]) << 8)
            : (clampByte(bytes[i]) << 8) | clampByte(bytes[i + 1]);
        if (code === 0) {
            break;
        }
        text += String.fromCharCode(code);
    }
    return text;
}

declare global {
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
        const sourceApi = s instanceof NativePointer ? s.api : undefined;
        this.api = api ?? sourceApi ?? R;
        this.addr =
            s === undefined
                ? "$$"
                : s instanceof NativePointer
                  ? s.addr.trim()
                  : ("" + s).trim();
    }
    private formatPointer(value: NativePointerValue): string {
        return value instanceof NativePointer ? value.addr.trim() : ("" + value).trim();
    }
    private newPointer(value: NativePointerValue): NativePointer {
        return new NativePointer(value, this.api);
    }
    private formatInteger(value: number | string | bigint): string {
        return typeof value === "bigint" ? value.toString() : ("" + value).trim();
    }
    private async isBigEndian(): Promise<boolean> {
        const output = await this.api.call("e cfg.bigendian");
        return output.trim() === "true";
    }
    private async readInteger(
        byteLength: number,
        signed: boolean,
        littleEndian?: boolean
    ): Promise<bigint> {
        const data = await this.readByteArray(byteLength);
        const useLittleEndian = littleEndian ?? !(await this.isBigEndian());
        return signed
            ? bytesToSignedBigInt(data, useLittleEndian)
            : bytesToUnsignedBigInt(data, useLittleEndian);
    }
    private async writeInteger(
        value: number | string | bigint,
        byteLength: number,
        signed: boolean,
        littleEndian?: boolean
    ): Promise<boolean> {
        const useLittleEndian = littleEndian ?? !(await this.isBigEndian());
        const bigintValue = parseInteger(value);
        const bytes = signed
            ? signedBigIntToBytes(bigintValue, byteLength, useLittleEndian)
            : unsignedBigIntToBytes(bigintValue, byteLength, useLittleEndian);
        await this.writeByteArray(bytes);
        return true;
    }
    private async pointerSize(): Promise<number> {
        const output = await this.api.cmd("e asm.bits");
        return Math.max(1, parseInt(output.trim(), 10) / 8);
    }
    /**
     * Copy N bytes from current pointer to the destination
     *
     * @param {string|NativePointer|number} destination address
     * @param {string|number} amount of bytes
     */
    async copyTo(addr: NativePointerValue, size: string | number): Promise<void> {
        await this.api.cmd(`wf ${this.addr} ${size} @ ${this.formatPointer(addr)}`);
    }
    /**
     * Copy N bytes from given address to the current destination
     *
     * @param {string|NativePointer|number} source address
     * @param {string|number} amount of bytes
     */
    async copyFrom(addr: NativePointerValue, size: string | number): Promise<void> {
        await this.api.cmd(`wf ${this.formatPointer(addr)} ${size} @ ${this.addr}`);
    }
    /**
     * Fill N bytes in this address with zero
     *
     * @param {string|number} amount of bytes
     */
    async zeroFill(size: string | number): Promise<void> {
        await this.api.cmd(`w0 ${size} @ ${this.addr}`);
    }
    /**
     * Filter a string to be used as a valid flag name
     *
     * @param {string} name of the symbol name
     * @returns {string} filtered name to be used as a flag
     */
    async filterFlag(name: string): Promise<string> {
        return this.api.call(`fD ${name}`);
    }
    /**
     * Set a flag (name) at the address pointed
     *
     * @param {string} name of the flag to set
     * @returns {string} base64 decoded string
     */
    async setFlag(name: string) {
        await this.api.call(`f ${name}=${this.addr}`);
    }
    /**
     * Remove the flag in the current address
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
        if (len <= 0) {
            return [];
        }
        return this.api.cmdj(`p8j ${len}@${this.addr}`);
    }
    async readHexString(len: number): Promise<string> {
        if (len <= 0) {
            return "";
        }
        const output = await this.api.cmd(`p8 ${len}@${this.addr}`);
        return output.trim();
    }
    async slice(length: number): Promise<number[]> {
        return this.readByteArray(length);
    }
    async writeHexString(hex: string): Promise<NativePointer> {
        const normalized = normalizeHexString(hex);
        if (normalized !== "") {
            await this.api.cmd(`wx ${normalized} @ ${this.addr}`);
        }
        return this;
    }
    async and(a: number | string | bigint): Promise<NativePointer> {
        const addr = await this.api.call(`?v ${this.addr} & ${this.formatInteger(a)}`);
        return this.newPointer(addr.trim());
    }
    async or(a: number | string | bigint): Promise<NativePointer> {
        const addr = await this.api.call(`?v ${this.addr} | ${this.formatInteger(a)}`);
        return this.newPointer(addr.trim());
    }
    async add(a: number | string | bigint): Promise<NativePointer> {
        const addr = await this.api.call(`?v ${this.addr} + ${this.formatInteger(a)}`);
        return this.newPointer(addr.trim());
    }
    async sub(a: number | string | bigint): Promise<NativePointer> {
        const addr = await this.api.call(`?v ${this.addr} - ${this.formatInteger(a)}`);
        return this.newPointer(addr.trim());
    }
    async distance(a: NativePointerValue): Promise<bigint> {
        return (await this.toBigInt()) - (await this.newPointer(a).toBigInt());
    }
    async writeByteArray(data: ArrayLike<number>): Promise<NativePointer> {
        const hex = byteArrayToHex(data);
        if (hex !== "") {
            await this.api.cmd(`wx ${hex} @ ${this.addr}`);
        }
        return this;
    }
    async patchByteArray(data: ArrayLike<number>): Promise<NativePointer> {
        return this.writeByteArray(data);
    }
    async patchHexString(hex: string): Promise<NativePointer> {
        return this.writeHexString(hex);
    }
    async writeAssembly(instruction: string): Promise<NativePointer> {
        await this.api.cmd(`wa ${instruction} @ ${this.addr}`);
        return this;
    }
    async patchInstruction(instruction: string): Promise<NativePointer> {
        return this.writeAssembly(instruction);
    }
    async writeString(s: string): Promise<NativePointer> {
        return this.writeUtf8String(s, false);
    }
    async writeUtf8String(s: string, zeroTerminated: boolean = false): Promise<NativePointer> {
        return this.writeByteArray(encodeUtf8String(s, zeroTerminated));
    }
    async writeCString(s: string): Promise<NativePointer> {
        return this.writeUtf8String(s, true);
    }
    async writeUtf16String(
        s: string,
        zeroTerminated: boolean = false,
        littleEndian?: boolean
    ): Promise<NativePointer> {
        const useLittleEndian = littleEndian ?? !(await this.isBigEndian());
        return this.writeByteArray(encodeUtf16String(s, useLittleEndian, zeroTerminated));
    }
    async writeWideString(s: string): Promise<NativePointer> {
        return this.writeUtf16String(s, true);
    }
    async patchCString(s: string): Promise<NativePointer> {
        return this.writeCString(s);
    }
    async patchWideString(s: string): Promise<NativePointer> {
        return this.writeWideString(s);
    }
    async patchData(data: ArrayLike<number> | string): Promise<NativePointer> {
        if (typeof data === "string") {
            return this.writeHexString(data);
        }
        return this.writeByteArray(data);
    }
    async readString(length?: number): Promise<string> {
        if (length === undefined) {
            return this.readCString();
        }
        return this.readUtf8String(length);
    }
    async readUtf8String(length?: number): Promise<string> {
        if (length === undefined) {
            const output = await this.api.cmdj(`pszj@${this.addr}`);
            return output.string;
        }
        return decodeUtf8Bytes(await this.readByteArray(length));
    }
    async readUtf16String(length?: number, littleEndian?: boolean): Promise<string> {
        if (length === undefined) {
            return this.readWideString();
        }
        const useLittleEndian = littleEndian ?? !(await this.isBigEndian());
        return decodeUtf16Bytes(await this.readByteArray(length), useLittleEndian);
    }
    /**
     * Check if it's a pointer to the address zero. Also known as null pointer.
     *
     * @returns {boolean} true if null
     */
    async isNull(): Promise<boolean> {
        return (await this.toBigInt()) === 0n;
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
    async compare(a: NativePointerValue): Promise<number> {
        const lhs = await this.toBigInt();
        const rhs = await this.newPointer(a).toBigInt();
        if (lhs < rhs) {
            return -1;
        }
        if (lhs > rhs) {
            return 1;
        }
        return 0;
    }
    async equals(a: NativePointerValue): Promise<boolean> {
        return (await this.compare(a)) === 0;
    }
    async isBelow(a: NativePointerValue): Promise<boolean> {
        return (await this.compare(a)) < 0;
    }
    async isAbove(a: NativePointerValue): Promise<boolean> {
        return (await this.compare(a)) > 0;
    }
    /**
     * Check if it's a pointer to the address zero. Also known as null pointer.
     *
     * @returns {boolean} true if null
     */
    async pointsToNull(): Promise<boolean> {
        const value = await this.readPointer();
        return value.isNull();
    }
    async toJSON(): Promise<string> {
        const output = await this.api.cmd("?vi " + this.addr.trim());
        return output.trim();
    }
    async toString(): Promise<string> {
        const output = await this.api.cmd("?v " + this.addr.trim());
        return output.trim();
    }
    async toBigInt(): Promise<bigint> {
        return BigInt(await this.toJSON());
    }
    async toNumber(): Promise<number> {
        return bigintToSafeNumber(await this.toBigInt(), "NativePointer.toNumber");
    }
    async writePointer(p: NativePointerValue): Promise<boolean> {
        await this.api.cmd(`wvp ${this.formatPointer(p)} @ ${this.addr}`);
        return true;
    }
    async readRelativePointer(): Promise<NativePointer> {
        return this.add(await this.readS32());
    }
    async readPointer(): Promise<NativePointer> {
        const address = await this.api.cmd(`pvp@${this.addr}`);
        return this.newPointer(address.trim());
    }
    async follow(levels: number = 1): Promise<NativePointer> {
        let current: NativePointer = this;
        for (let i = 0; i < levels; i++) {
            current = await current.readPointer();
        }
        return current;
    }
    async readPointers(count: number): Promise<NativePointer[]> {
        const pointers: NativePointer[] = [];
        const step = await this.pointerSize();
        let current: NativePointer = this;
        for (let i = 0; i < count; i++) {
            pointers.push(await current.readPointer());
            current = await current.add(step);
        }
        return pointers;
    }
    async readS8(): Promise<number> {
        return bigintToSafeNumber(await this.readInteger(1, true), "readS8");
    }
    async readU8(): Promise<number> {
        return bigintToSafeNumber(await this.readInteger(1, false), "readU8");
    }
    async readU16(): Promise<number> {
        return bigintToSafeNumber(await this.readInteger(2, false), "readU16");
    }
    async readU16le(): Promise<number> {
        return bigintToSafeNumber(await this.readInteger(2, false, true), "readU16le");
    }
    async readU16be(): Promise<number> {
        return bigintToSafeNumber(await this.readInteger(2, false, false), "readU16be");
    }
    async readS16(): Promise<number> {
        return bigintToSafeNumber(await this.readInteger(2, true), "readS16");
    }
    async readS16le(): Promise<number> {
        return bigintToSafeNumber(await this.readInteger(2, true, true), "readS16le");
    }
    async readS16be(): Promise<number> {
        return bigintToSafeNumber(await this.readInteger(2, true, false), "readS16be");
    }
    async readS32(): Promise<number> {
        return bigintToSafeNumber(await this.readInteger(4, true), "readS32");
    }
    async readS32le(): Promise<number> {
        return bigintToSafeNumber(await this.readInteger(4, true, true), "readS32le");
    }
    async readS32be(): Promise<number> {
        return bigintToSafeNumber(await this.readInteger(4, true, false), "readS32be");
    }
    async readU32(): Promise<number> {
        return bigintToSafeNumber(await this.readInteger(4, false), "readU32");
    }
    async readU32le(): Promise<number> {
        return bigintToSafeNumber(await this.readInteger(4, false, true), "readU32le");
    }
    async readU32be(): Promise<number> {
        return bigintToSafeNumber(await this.readInteger(4, false, false), "readU32be");
    }
    async readU64BigInt(): Promise<bigint> {
        return this.readInteger(8, false);
    }
    async readU64leBigInt(): Promise<bigint> {
        return this.readInteger(8, false, true);
    }
    async readU64beBigInt(): Promise<bigint> {
        return this.readInteger(8, false, false);
    }
    async readU64(): Promise<number> {
        return bigintToSafeNumber(await this.readU64BigInt(), "readU64");
    }
    async readU64le(): Promise<number> {
        return bigintToSafeNumber(await this.readU64leBigInt(), "readU64le");
    }
    async readU64be(): Promise<number> {
        return bigintToSafeNumber(await this.readU64beBigInt(), "readU64be");
    }
    async readU64String(): Promise<string> {
        return (await this.readU64BigInt()).toString();
    }
    async readU64leString(): Promise<string> {
        return (await this.readU64leBigInt()).toString();
    }
    async readU64beString(): Promise<string> {
        return (await this.readU64beBigInt()).toString();
    }
    async readS64(): Promise<bigint> {
        return this.readInteger(8, true);
    }
    async readS64le(): Promise<bigint> {
        return this.readInteger(8, true, true);
    }
    async readS64be(): Promise<bigint> {
        return this.readInteger(8, true, false);
    }
    async readS64String(): Promise<string> {
        return (await this.readS64()).toString();
    }
    async readS64leString(): Promise<string> {
        return (await this.readS64le()).toString();
    }
    async readS64beString(): Promise<string> {
        return (await this.readS64be()).toString();
    }
    async writeInt(n: number | string | bigint): Promise<boolean> {
        return this.writeS32(n);
    }
    /**
     * Write a byte in the current address, the value must be between 0 and 255
     *
     * @param {string} n number to write in the pointed byte in the current address
     * @returns {boolean} false if the operation failed
     */
    async writeU8(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 1, false);
    }
    async writeS8(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 1, true);
    }
    async writeU16(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 2, false);
    }
    async writeU16be(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 2, false, false);
    }
    async writeU16le(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 2, false, true);
    }
    async writeS16(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 2, true);
    }
    async writeS16be(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 2, true, false);
    }
    async writeS16le(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 2, true, true);
    }
    async writeU32(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 4, false);
    }
    async writeU32be(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 4, false, false);
    }
    async writeU32le(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 4, false, true);
    }
    async writeS32(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 4, true);
    }
    async writeS32be(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 4, true, false);
    }
    async writeS32le(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 4, true, true);
    }
    async writeU64(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 8, false);
    }
    async writeU64be(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 8, false, false);
    }
    async writeU64le(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 8, false, true);
    }
    async writeS64(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 8, true);
    }
    async writeS64be(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 8, true, false);
    }
    async writeS64le(n: number | string | bigint): Promise<boolean> {
        return this.writeInteger(n, 8, true, true);
    }
    async readInt32(): Promise<number> {
        return this.readS32();
    }
    async readCString(): Promise<string> {
        const output = await this.api.cmdj(`pszj@${this.addr}`);
        return output.string;
    }
    async readWideString(): Promise<string> {
        const output = await this.api.cmdj(`pswj@${this.addr}`);
        return output.string;
    }
    async readPascalString(): Promise<string> {
        const output = await this.api.cmdj(`pspj@${this.addr}`);
        return output.string;
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
