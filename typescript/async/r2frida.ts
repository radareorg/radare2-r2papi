import { R2Pipe, R2PipeAsync, newAsyncR2PipeFromSync } from "./r2pipe.js";
import { NativePointer } from "./index.js";

declare global {
    // eslint-disable-next-line no-var
    var r2: R2Pipe;
}

export class R2Frida {
    isAvailable: boolean;
    r2: R2PipeAsync;
    constructor(r2: R2PipeAsync) {
        this.r2 = r2;
        this.isAvailable = false;
    }
    async checkAvailability() {
        if (!this.isAvailable) {
            const output = await r2.cmd("o~frida://");
            if (output.trim() === "") {
                throw new Error("There's no frida session available");
            }
        }
        this.isAvailable = true;
    }

    async eval(expr: string): Promise<string> {
        return r2.cmd(`"": ${expr}`);
    }
    async targetDetails(): Promise<TargetDetails> {
        return r2.cmdj(":ij") as TargetDetails;
    }
    async continue(): Promise<void> {
        r2.cmd(":dc");
    }
    async enumerateClasses(): Promise<string[]> {
        return r2.callj(":icj");
    }
    async enumerateMethods(className: string): Promise<Map<string, NativePointer>> {
        return r2.callj(`:icj ${className}`);
    }
    async enumerateApplicationClasses(): Promise<string[]> {
        const applicationName = (await r2.callj(":icj")).name;
        return r2.callj(`:icj~${applicationName}`).map((res: string) => res.split(" ")[1]);
    }
    async enumerateExports(): Promise<ExportSymbol[]> {
        return r2.callj(":iEj");
    }
    async enumerateImports(): Promise<ImportSymbol[]> {
        return r2.callj(":iij");
    }
    async enumerateSymbols() : Promise<Symbol[]> {
        return r2.callj(":isj");
    }
    async enumerateEntrypoints() : Promise<EntryPoint[]> {
        return r2.callj(":iej");
    }
    async enumerateMemoryRegions() : Promise<MemoryRegion[]> {
        return r2.callj(":dmj");
    }
    async enumerateMemoryRanges() : Promise<MemoryRange[]> {
        return r2.callj(":dmmj");
    }
    // async interceptObjCMethod(className: string, methodName: string): Promise<any> {
    //     return r2.cmdj(":dt") as TargetDetails;
    // }
    // async interceptJavaMethod(className: string, methodName: string): Promise<TargetDetails> {
    //     return r2.cmdj(":ij") as TargetDetails;
    // }
    // async interceptFunction(pointer: NativePointer): Promise<TargetDetails> {
    //     return r2.cmdj(":ij") as TargetDetails;
    // }
}

/*
export async function main() {
    console.log("Hello from r2papi-r2frida");
    const r2async = newAsyncR2PipeFromSync(r2);
    const r2f = new R2Frida(r2async);
    r2f.eval("console.log(123);");
    const { pid, arch, cwd } = await r2f.targetDetails();
    console.log(pid, arch, cwd);
}
main();
*/

export interface TargetDetails {
    arch: string;
    bits: number;
    os: string;
    pid: number;
    uid: number;
    runtime: string;
    objc: boolean;
    swift: boolean;
    mainLoop: boolean;
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
    bundledir?: any;
}

export interface ExportSymbol {
    type: "variable" | "function";
    name: string;
    address: NativePointer;
}

export interface ImportSymbol {
    type: "variable" | "function";
    name: string;
    module: string;
    address: NativePointer;
    slot: NativePointer;
    index: number;
    targetModuleName: string | null;
}

export interface Symbol {
    isGlobal: boolean;
    type: "section" | "variable" | "function" | "undefined";
    name: string;
    address: NativePointer;
    section?: SectionDetails
}

export interface SectionDetails {
    id: string;
    protection: string;
}

export interface EntryPoint {
    type: "function";
    name: string;
    address: NativePointer;
    moduleName: string;
}

export interface MemoryRegion {
    base: NativePointer;
    size: number;
    protection: string;
}

export interface MemoryRange {
    base: NativePointer;
    size: number;
    protection: string;
    file: RangeMap;
}

export interface RangeMap {
    path: string;
    offset: number;
    size: number;
}