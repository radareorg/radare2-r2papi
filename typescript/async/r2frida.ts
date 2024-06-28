import { R2Pipe, R2PipeAsync, newAsyncR2PipeFromSync } from "./r2pipe.js";

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
