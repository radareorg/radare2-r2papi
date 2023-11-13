export class Base64 {
	static encode(x: string) : string {
		return b64(x);
	}
	static decode(x: string) : string {
		return b64(x, true);
	}
}

interface base64Interface {
	(message: string, decode?: boolean): string;
}

export declare var b64: base64Interface;
