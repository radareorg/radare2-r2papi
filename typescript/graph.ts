declare var r2: any;

class Graph {
	constructor () {
		r2.cmd("ag-");
	}
	addNode(title: string, body: string) {
		r2.cmd(`agn ${title} ${body}`);
	}
	addEdge(a: string, b: string) {
		r2.cmd(`age ${a} ${b}`);
	}
	toString() {
		return r2.cmd("agg");
	}
}

export function main() {
	var g = new Graph();

	g.addNode("hello", "World");
	g.addNode("world", "Hello");
	g.addNode("patata", "Hello");
	g.addEdge("hello", "world");
	g.addEdge("hello", "patata");
	g.addEdge("world", "world");

	console.log(g);
}
main();
