import * as r2pipe from "r2pipe-promise";

class R2 {
	public r2 = undefined;
	private path = "";

	public Memory

	constructor(path: string) {
		this.path = path;
	}
	async connect() {
		this.r2 = await r2pipe.open(this.path);
	}
	
	public async cmd(cmd: string) {
		if (this.r2 !== undefined) {
			return this.r2.cmd(cmd)
		}
	}

	public async cmdj(cmd: string) {
		return JSON.parse(await this.cmd(cmd));
	}

	public async quit() {
		await this.r2.quit();
	}

	public async memoryWriteBytes(addr:string | number, arg: [number]) {
		return await this.cmd("w " + arg + " @ " + addr);
	}

	public async memoryWriteString(addr:string | number, arg: string) {
		return await this.cmd("w " + arg + " @ " + addr);
	}

	public async memoryWriteAssembly(addr:string | number, arg: string) {
		return await this.cmd("wa " + arg + " @ " + addr);
	}

	public async memoryRead(addr:string | number, len: number) {
		return await this.cmdj("p8j " + len + " @ " + addr);
	}

	/// configuration

	public async configGet(key: string) {
		return await this.cmd("e " + key);
	}

	public async configSet(key:string, val: string | bool | number) {
		return await this.cmd("e " + key + " = " + val);
	}
}

async function main() {
  var r2 = new R2("/bin/ls");
  await r2.connect();
  await r2.cmd("e io.cache=true");
  var bytes = await r2.memoryRead('entry0', 32);

  await r2.memoryWriteString('entry0', "Hello World");

  await r2.memoryWriteAssembly("entry0", "mov x0, 0,,ret")
  const asmArch = await r2.configGet("asm.arch");
  await r2.configSet("asm.arch", "arm");
  await r2.configSet("asm.bits", 32);
  console.log("ARCH: ", asmArch);

console.error("Byets", bytes);
  r2.quit();

}

Promise.resolve(main());
