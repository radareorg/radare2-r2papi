// shell utilities on top of r2pipe

import { R2Papi } from "./r2papi.js";
import type { FileSystemPlugin, MountPoint, MountsOutput } from "./outputs.js";

/** Escape a string for safe use as a single POSIX shell word. */
function shQuote(s: string): string {
    return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

/**
 * Describes an available virtual filesystem plugin.
 *
 * @deprecated Use FileSystemPlugin (from outputs.js) instead. The old
 * `description` field never matched what `mLj` actually returns; the real
 * field is `desc`.
 *
 * @typedef FileSystemType
 */
export type FileSystemType = FileSystemPlugin;

/**
 * Global static class providing information about the actual radare2 in use.
 * This class mimics the `Frida` global object in frida, which can be useful to
 * determine the executing environment of the script
 *
 * @typedef Radare2
 */
export interface Radare2 {
    /**
     * string representing the radare2 version (3 numbers separated by dots)
     *
     * @type {string}
     */
    version: string;
}

/**
 * Class that interacts with the `r2ai` plugin (requires `rlang-python` and `r2i` r2pm packages to be installed).
 * Provides a way to script the interactions with different language models using javascript from inside radare2.
 *
 * @typedef R2Shell
 */
export class R2Shell {
    /**
     * Keep a reference to the associated r2papi instance
     *
     * @type {R2Papi}
     */
    public rp: R2Papi;

    /**
     * Create a new instance of the R2Shell
     *
     * @param {R2Papi} take the R2Papi intance to used as backend to run the commands
     * @returns {R2Shell} instance of the shell api
     */
    constructor(papi: R2Papi) {
        this.rp = papi;
    }

    /**
     * Create a new directory in the host system, if the opational recursive argument is set to
     * true it will create all the necessary subdirectories instead of just the specified one.
     *
     * @param {string} text path to the new directory to be created
     * @param {boolean?} disabled by default, but if it's true, it will create subdirectories recursively if necessary
     * @returns {boolean} true if successful
     */
    async mkdir(file: string, recursive?: boolean): Promise<boolean> {
        const flag = recursive === true ? "-p " : "";
        await this.rp.call(`!mkdir ${flag}${shQuote(file)}`);
        return true;
    }

    /**
     * Deletes a file
     *
     * @param {string} file path to the file to remove
     * @returns {boolean} true if successful
     */
    async unlink(file: string): Promise<boolean> {
        await this.rp.call(`!rm -f ${shQuote(file)}`);
        return true;
    }

    /**
     * Change current directory
     *
     * @param {string} path to the directory
     * @returns {boolean} true if successful
     */
    async chdir(path: string): Promise<boolean> {
        await this.rp.call(`cd ${path}`);
        return true;
    }

    /**
     * List files in the current directory
     *
     * @returns {string[]} array of file names
     */
    async ls(): Promise<string[]> {
        const files = await this.rp.call("!ls -1A");
        return files.split("\n").map((x) => x.trim()).filter((x) => x.length > 0);
    }

    /**
     * Checks if a file exists on the host filesystem.
     *
     * @returns {boolean} true if the file exists, false if it does not
     */
    async fileExists(path: string): Promise<boolean> {
        const out = await this.rp.call(`!test -e ${shQuote(path)} && echo 1 || echo 0`);
        return out.trim().endsWith("1");
    }

    /**
     * Opens an URL or application
     * Execute `xdg-open` on linux, `start` on windows, `open` on Mac
     *
     * @param {string} arg URI or file to open by the system
     */
    async open(arg: string): Promise<void> {
        const quoted = shQuote(arg);
        // try the common openers in order of likelihood
        await this.rp.call(`!open ${quoted} 2>/dev/null || xdg-open ${quoted} 2>/dev/null || start ${quoted}`);
    }

    /**
     * Run a system command and get its exit code. Stdout/stderr pass through.
     *
     * @param {string} cmd command to be executed by the host shell
     * @returns {number} return code (0 is success)
     */
    async system(cmd: string): Promise<number> {
        const out = await this.rp.call(`!sh -c ${shQuote(cmd + "; echo __r2papi_rc=$?")}`);
        const m = /__r2papi_rc=(\d+)/.exec(out);
        return m ? parseInt(m[1], 10) : -1;
    }

    /**
     * Mount the given offset on the specified path using the filesytem.
     * This is not a system-level mountpoint, it's using the internal filesystem abstraction of radare2.
     *
     * @param {string} fstype filesystem type name (see `mLj`)
     * @param {string} path where to mount the filesystem
     * @param {string|number} addr address offset of the filesystem
     * @returns {boolean} true if the mount command was sent
     */
    async mount(fstype: string, path: string, addr: string | number): Promise<boolean> {
        await this.rp.call(`m ${fstype} ${path} ${addr ?? 0}`);
        return true;
    }
    /**
     * Unmount the mountpoint associated with the given path.
     *
     * @param {string} path to the mounted filesystem
     * @returns {void} TODO: should return boolean
     */
    async umount(path: string): Promise<void> {
        await this.rp.call(`m-${path}`);
    }
    /**
     * Change current directory on the internal radare2 filesystem
     *
     * @param {string} path name to change to
     * @returns {void} TODO: should return boolean
     */
    async chdir2(path: string): Promise<void> {
        await this.rp.call(`mdq ${path}`);
    }
    /**
     * List the files contained in the given path within the virtual radare2 filesystem.
     *
     * @param {string} path name to change to
     * @returns {void} TODO: should return boolean
     */
    async ls2(path: string): Promise<string[]> {
        const files = await this.rp.call(`mdq ${path}`);
        return files.trim().split("\n");
    }
    /**
     * Enumerate the virtual filesystem plugins available in r2
     * @returns {FileSystemPlugin[]} array of filesystem plugins (the `mLj` output)
     */
    async enumerateFilesystemTypes(): Promise<FileSystemPlugin[]> {
        return this.rp.cmdj("mLj");
    }
    /**
     * Enumerate all the mountpoints set in the internal virtual filesystem of radare2
     * @returns {MountPoint[]} array of mountpoints (the `mountpoints` key of the `mj` output)
     */
    async enumerateMountpoints(): Promise<MountPoint[]> {
        const output: MountsOutput = await this.rp.cmdj("mj");
        return (output && output.mountpoints) || [];
    }
    /**
     * Check if a path is a symbolic link on the host filesystem.
     */
    async isSymlink(file: string): Promise<boolean> {
        const out = await this.rp.call(`!test -L ${shQuote(file)} && echo 1 || echo 0`);
        return out.trim().endsWith("1");
    }
    /**
     * Check if a path is a directory on the host filesystem.
     */
    async isDirectory(file: string): Promise<boolean> {
        const out = await this.rp.call(`!test -d ${shQuote(file)} && echo 1 || echo 0`);
        return out.trim().endsWith("1");
    }
}
