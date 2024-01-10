declare var r2: any;

class Graph {
	constructor () {
		r2.cmd("ag-");
	}

	/**
     * Add a node into the graph
	 *
	 * @param {string} title label of the node, this label must be unique to the graph
	 * @param {string} body contents of the node
     */
	addNode(title: string, body: string) {
		r2.cmd(`agn ${title} ${body}`);
	}

	/**
     * Add an edge linking two nodes referenced by the title
	 *
	 * @param {string} a source title node
	 * @param {string} b destination title node
     */
	addEdge(a: string, b: string) {
		r2.cmd(`age ${a} ${b}`);
	}

	/**
     * Get an ascii art representation of the graph as a string
	 *
     * @returns {string} the computed graph
     */
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
