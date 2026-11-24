/**
 * Typed shapes for the JSON outputs of radare2 commands (the commands ending
 * in `j`). These describe what the commands actually emit on modern
 * radare2 (6.x), not what we wish they emitted. Fields that depend on the
 * file format, architecture or configuration are marked optional.
 *
 * If you find a mismatch with a real output, fix the interface and the
 * producer in `r2papi.ts` at the same time. `tools/tsi.sh` can be used
 * to bootstrap new interfaces from live output.
 */

/** `omj` — memory map entries */
export interface MapEntry {
    map: number;
    fd: number;
    delta: number;
    from: number;
    to: number;
    /** currently-effective permissions, like "rwx" */
    perm: string;
    /** permissions the map was requested with */
    sperm: string;
    name: string;
}

/** `oj` — opened files */
export interface OpenedFile {
    raised: boolean;
    fd: number;
    uri: string;
    from: number;
    writable: boolean;
    size: number;
}

/** `obj` — opened binary objects */
export interface BinObject {
    name: string;
    iofd: number;
    bfid: number;
    size: number;
    /** base address of the object */
    addr: number;
    obj: {
        arch: string;
        bits: number;
        binoffset: number;
        objsize: number;
    };
}

/** `iSj` — sections */
export interface Section {
    name: string;
    size: number;
    vsize: number;
    type: string;
    perm: string;
    flags: number;
    paddr: number;
    vaddr: number;
}

/** `iSSj` — segments */
export interface Segment {
    name: string;
    size: number;
    vsize: number;
    perm: string;
    flags: number;
    paddr: number;
    vaddr: number;
}

/** `irj` — relocations */
export interface Relocation {
    type: string;
    ntype: number;
    vaddr: number;
    paddr: number;
    is_ifunc: boolean;
    /** present on some formats (ELF) */
    addend?: number;
    /** symbol name, present when the relocation binds to a symbol */
    symbol?: string;
}

/** `iej` — entrypoints */
export interface Entrypoint {
    paddr: number;
    vaddr: number;
    baddr: number;
    laddr: number;
    hvaddr: number;
    haddr: number;
    type: string;
}

/** `iij` — imports */
export interface ImportSymbol {
    ordinal?: number;
    bind: string;
    type: string;
    sig?: boolean;
    name: string;
    plt?: number;
}

/** `iEj` / `isj` — exports and symbols. They share the same layout. */
export interface SymbolInfo {
    name: string;
    flagname?: string;
    realname?: string;
    ordinal?: number;
    bind: string;
    size: number;
    type: string;
    vaddr: number;
    paddr: number;
    is_imported: boolean;
}

/** `icj` — class hierarchy information. Shape depends on the loader */
export type ClassInfo = Record<string, unknown>;

/** `mj` — a single virtual filesystem mountpoint */
export interface MountPoint {
    path: string;
    plugin: string;
    offset: number;
}

/** `mj` — root object of the virtual filesystem mounts */
export interface MountsOutput {
    mountpoints: MountPoint[];
    plugins?: FileSystemPlugin[];
}

/** `mLj` — available virtual filesystem plugins */
export interface FileSystemPlugin {
    name: string;
    desc: string;
    author?: string;
    license?: string;
}

/** `L*j` — list plugins. The exact fields depend on the plugin family. */
export interface PluginInfo {
    name: string;
    desc: string;
    author?: string;
    license?: string;
    version?: string;
    path?: string;
    /** arch plugins (`LAj`) */
    arch?: string;
    endian?: string;
    bits?: number[];
    cpus?: string[];
    /** io plugins (`Loj`) */
    permissions?: string;
    uris?: string[];
    /** anal plugins (`Laj`) */
    score?: number;
    eligible?: boolean;
    analyze_fcn?: boolean;
    recover_vars?: boolean;
    post_analysis?: boolean;
}

/** `Lij` — bin plugins are wrapped in an object keyed by family */
export interface BinPluginsOutput {
    bin?: PluginInfo[];
}

/** `drj` — register dump, flat name/value map */
export type RegisterDump = Record<string, number>;

/** `dptj` — debugged threads */
export interface DebugThread {
    current?: boolean;
    pid?: number;
    status?: string;
    path?: string;
    [key: string]: unknown;
}
