import { r2, Base64, R2Pipe, R2Papi } from "r2papi";

interface Entry {
	address: string;
	fileLine: string;
	fcnName: string;
	action: string;
};

function parseAsan(text: string) {
	const lines = text.split('\n');
	let btid = "";
	let r2s = "";
	var papi = new R2Papi(r2);

	let nodes = new Map<string, string[]>();
	let edges = "";
	let prev = undefined;
	for (let line of lines) {
		line.trim();
		line = line.replace(/^ */, '');
		if (line.startsWith("READ of")) {
			btid = "READ";
		} else if (line.startsWith("freed by thread")) {
			btid = "FREE";
		} else if (line.startsWith("previously allocated")) {
			btid = "ALLOC";
		} else if (line[0] === '#') {
			const words = line.split(' ');
			const entry: Entry = {
				address: words[1] || '',
				fcnName: words[3] || '',
				fileLine: words[4] || '',
				action: btid,
			};
			if (entry.fcnName.indexOf('<') === -1) {
				const line = entry.action + ' ' + entry.fileLine;
				const uses = nodes.get(entry.fcnName) ?? [];
				if (uses.indexOf(line) === -1) {
					uses.push(line);
				}
				nodes.set(entry.fcnName, uses);
				if (prev !== undefined) {
					edges += "age " + entry.fcnName + " " + prev.fcnName + "\n";
				}
			}
			prev = entry;
		}
	}
	for (let entry of nodes.entries ()) {
		const body = Base64.encode(entry[1].join("\n"));
		console.log(body);
		r2s += "agn " + entry[0] + " base64:" + body + "\n";
	}
	r2s += edges;
	return r2s;
}

function main(r2:R2Pipe) {
	const crash_txt = r2.cmd("cat crash.txt");
	const r2script = parseAsan(crash_txt);
	// console.log(r2script);
	for (let line of r2script.split(/\n/g)) {
		r2.cmd(line);
	}
	// graphviz dot
	console.log(r2.cmd("aggd"));
	// ascii art graph
	console.log(r2.cmd("agg"));
}

main(r2);
