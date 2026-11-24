import { R2PipeAsync } from "./r2pipe.js";
import type {
    FridaClassMembers, FridaExport, FridaImport, FridaSymbol, FridaEntryPoint,
    FridaMemoryRange, FridaMemoryMap, TargetDetails,
} from "./outputs.js";
export type { TargetDetails } from "./outputs.js";

export class R2Frida {
    isAvailable: boolean;
    r2: R2PipeAsync;
    constructor(r2: R2PipeAsync) {
        this.r2 = r2;
        this.isAvailable = false;
    }
    async checkAvailability(): Promise<void> {
        if (!this.isAvailable) {
            const output = await this.r2.cmd("o~frida://");
            if (output.trim() === "") {
                throw new Error("There's no frida session available");
            }
            this.isAvailable = true;
        }
    }

    async eval(expr: string): Promise<string> {
        return this.r2.call(`: ${expr}`);
    }
    async targetDetails(): Promise<TargetDetails> {
        return this.r2.callj(":ij");
    }
    async continue(): Promise<void> {
        await this.r2.call(":dc");
    }
    async enumerateClasses(): Promise<string[]> {
        return this.r2.callj(":icj");
    }
    /** Objective-C returns method addresses; Java returns member signatures. */
    async enumerateMethods(className: string): Promise<FridaClassMembers> {
        // r2frida splits arguments on spaces and does not unquote them.
        if (!className || /\s/.test(className)) {
            throw new Error("Expected a single class name");
        }
        return this.r2.callj(`:icj ${className}`);
    }
    /** Android package classes, or Objective-C classes in the current module. */
    async enumerateApplicationClasses(): Promise<string[]> {
        return this.r2.callj(":icj.");
    }
    async enumerateExports(): Promise<FridaExport[]> {
        return this.r2.callj(":iEj");
    }
    async enumerateImports(): Promise<FridaImport[]> {
        return this.r2.callj(":iij");
    }
    async enumerateSymbols(): Promise<FridaSymbol[]> {
        return this.r2.callj(":isj");
    }
    async enumerateEntrypoints(): Promise<FridaEntryPoint[]> {
        return this.r2.callj(":iej");
    }
    /** All memory ranges, including anonymous allocations. */
    async enumerateMemoryRanges(): Promise<FridaMemoryRange[]> {
        return this.r2.callj(":dmj");
    }
    /** Coalesced file-backed memory maps. */
    async enumerateMemoryMaps(): Promise<FridaMemoryMap[]> {
        return this.r2.callj(":dmmj");
    }
}
