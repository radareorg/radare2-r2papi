// shell utilities on top of r2pipe

import { R2Papi } from "./index.js";

export class R2PapiShell {
	public rp: R2Papi;

	constructor(papi: R2Papi) {
		this.rp = papi;
	}

	/**
	* Create a new directory in the host system, if the opational recursive argument is set to
	* true it will create all the necessary subdirectories instead of just the specified one.
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
 	*/
	unlink(file: string): boolean {
		this.rp.call (`rm ${file}`);
		return true;
	}

	/**
	* Change current directory
 	*/
	chdir(path:string) : boolean {
		this.rp.call (`cd ${path}`);
		return true;
	}

	ls(): string[] {
		return this.rp.call(`ls -q`).trim().split('\n')
	}

	fileExists(path: string) : boolean {
		// TODO
		return false;
	}
	/**
	* Opens an URL or application
	* calls `xdg-open` on linux, `start` on windows, `open` on Mac
 	*/
	open(arg: string): void {
		this.rp.call (`open ${arg}`);
	}

	system(cmd: string): number {
		this.rp.call (`!${cmd}`);
		return 0;
	}

	run(path: string): number {
		this.rp.call (`rm ${path}`);
		return 0;
	}
	mount(fstype: string, path: string) : boolean {
		this.rp.call (`m ${fstype} ${path}`);
		return true;
	}
	umount(path: string) : void {
		this.rp.call (`m-${path}`);
	}
	chdir2(path: string) : boolean {
		if (path === undefined) {
			path = "/";
		}
		this.rp.call (`mdq ${path}`);
		return true;
	}
	ls2(path: string) : string[] {
		if (path === undefined) {
			path = "/";
		}
		return this.rp.call (`mdq ${path}`).trim().split('\n');
	}
	enumerateMountpoints(): string[] {
		return this.rp.cmdj ("mlj");
	}
	isSymlink(file:string) : boolean {
		return false;
	}
	isDirectory(file:string) : boolean {
		return false;
	}
}
