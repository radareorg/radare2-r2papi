export type InstructionType = "mov" | "jmp" | "cmp" | "add" | "sub" | "swi" | "nop" | "call";
export type InstructionFamily = "cpu" | "fpu" | "priv";
export interface SearchResult {
    offset: number;
    type: string;
    data: string;
}
export interface Flag {
    name: string;
    size: number;
    offset: number;
}
export interface CallRef {
    addr: number;
    type: string;
    at: number;
}
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
    stack: string;
}
export interface R2Pipe {
    cmd(cmd: string): string;
    call(cmd: string): string;
    log(msg: string): string;
}
export declare class R2Api {
    r2: R2Pipe;
    constructor(r2: R2Pipe);
    clearScreen(): void;
    getRegisters(): any;
    setRegisters(obj: any): void;
    analyzeProgram(): void;
    hex(s: number | string): string;
    step(): R2Api;
    stepOver(): R2Api;
    math(expr: number | string): number;
    searchString(s: string): SearchResult[];
    binInfo(): BinFile;
    skip(): void;
    ptr(s: string | number): NativePointer;
    cmd(s: string): string;
    call(s: string): string;
    cmdj(s: string): any;
    log(s: string): string;
    clippy(msg: string): void;
    ascii(msg: string): void;
    listFunctions(): Function[];
    listFlags(): Flag[];
}
export declare class NativePointer {
    addr: string;
    api: R2Api;
    constructor(api: R2Api, s: string | number);
    readByteArray(len: number): any;
    add(a: number): NativePointer;
    sub(a: number): NativePointer;
    writeCString(s: string): NativePointer;
    readCString(): string;
    instruction(): Instruction;
    analyzeFunction(): void;
    name(): string;
    basicBlock(): BasicBlock;
    functionBasicBlocks(): BasicBlock[];
    xrefs(): Reference[];
}
