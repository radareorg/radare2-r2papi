declare module "r2pipe" {
	export class R2Pipe {
		cmd(string): string;
		cmdj(string): any;
		quit();
	}
	export function open(string?): R2Pipe;
}
