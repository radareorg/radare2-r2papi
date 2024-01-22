function JsonToTypescript(name: string, a: any) : string {
	let str = `interface ${name} {\n`;
	if (a.length && a.length > 0) {
		a = a[0];
	}
	for (let k of Object.keys(a)) {
		const typ = typeof (a[k]);
		const nam = k;
		str += `    ${nam}: ${typ};\n`;
	}
	return `${str}}\n`;
}


const res = JsonToTypescript("Test", {
name: "hello world",
bits: 32
		}
	);

console.log(res);
