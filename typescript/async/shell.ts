// shell utilities on top of r2pipe

import { R2Papi } from "./r2papi.js";

/**
 * Interface to hold the name and description for every filesystem type parser implementation.
 *
 * @typedef FileSystemType
 */
export interface FileSystemType {
	/**
	 * name of the filesystem format, to be used when mounting it.
	 *
	 * @type {string}
	 */
	name: string;
	/**
	 * short string that describes the plugin
	 *
	 * @type {string}
	 */
	description: string;
}

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
	constructor(papi: R2Papi) {
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
	mkdir(file: string, recursive?:boolean): boolean {
		if (recursive === true) {
			this.rp.call (`mkdir -p ${file}`);
		} else {
			this.rp.call (`mkdir ${file}`);
		}
		return true;
	}

	/**
	* Deletes a file
	*
        * @param {string} path to the file to remove
        * @returns {boolean} true if successful
 	*/
	unlink(file: string): boolean {
		this.rp.call (`rm ${file}`);
		return true;
	}

	/**
	* Change current directory
	*
        * @param {string} path to the directory
        * @returns {boolean} true if successful
 	*/
	chdir(path:string) : boolean {
		this.rp.call (`cd ${path}`);
		return true;
	}

	/**
	* List files in the current directory
	*
        * @returns {string[]} array of file names
 	*/
	ls(): string[] {
		return this.rp.call(`ls -q`).trim().split('\n')
	}

	/**
	* TODO: Checks if a file exists (not implemented)
	*
        * @returns {boolean} true if the file exists, false if it does not
 	*/
	fileExists(path: string) : boolean {
		// TODO
		return false;
	}

	/**
	* Opens an URL or application
	* Execute `xdg-open` on linux, `start` on windows, `open` on Mac
	*
        * @param {string} URI or file to open by the system
 	*/
	open(arg: string): void {
		this.rp.call (`open ${arg}`);
	}

	/**
	* Run a system command and get the return code
	*
        * @param {string} system command to be executed
        * @returns {number} return code (0 is success)
 	*/
	system(cmd: string): number {
		this.rp.call (`!${cmd}`);
		return 0;
	}

	/**
	* Mount the given offset on the specified path using the filesytem.
	* This is not a system-level mountpoint, it's using the internal filesystem abstraction of radare2.
	*
        * @param {string} filesystem type name (see .
        * @param {string} system command to be executed
        * @param {string|number}
        * @returns {number} return code (0 is success)
 	*/
	mount(fstype: string, path: string, offset: string|number) : boolean {
		if (!offset) {
			offset = 0;
		}
		this.rp.call (`m ${fstype} ${path} ${offset}`);
		return true;
	}
	/**
	* Unmount the mountpoint associated with the given path.
	*
        * @param {string} path to the mounted filesystem
        * @returns {void} TODO: should return boolean
 	*/
	umount(path: string) : void {
		this.rp.call (`m-${path}`);
	}
	/**
	* Change current directory on the internal radare2 filesystem
	*
        * @param {string} path name to change to
        * @returns {void} TODO: should return boolean
 	*/
	chdir2(path: string) : void {
		this.rp.call (`mdq ${path}`);
	}
	/**
	* List the files contained in the given path within the virtual radare2 filesystem.
	*
        * @param {string} path name to change to
        * @returns {void} TODO: should return boolean
 	*/
	ls2(path: string) : string[] {
		return this.rp.call (`mdq ${path}`).trim().split('\n');
	}
	/**
	 * Enumerate all the mountpoints set in the internal virtual filesystem of radare2
	 * @returns {any[]} array of mount
	 */
	enumerateFilesystemTypes(): any[] {
		return this.rp.cmdj ("mLj");
	}
	/**
	 * Enumerate all the mountpoints set in the internal virtual filesystem of radare2
	 * @returns {any[]} array of mount
	 */
	enumerateMountpoints(): any[] {
		return this.rp.cmdj ("mj")['mountpoints'];
	}
	/**
	 * TODO: not implemented
	 */
	isSymlink(file:string) : boolean {
		return false;
	}
	/**
	 * TODO: not implemented
	 */
	isDirectory(file:string) : boolean {
		return false;
	}
}
