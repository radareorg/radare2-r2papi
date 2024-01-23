declare let r2: any;

class Graph {
    constructor() {}
    async reset() {
        await r2.cmd("ag-");
    }

    /**
     * Add a node into the graph
     *
     * @param {string} title label of the node, this label must be unique to the graph
     * @param {string} body contents of the node
     */
    async addNode(title: string, body: string) {
        await r2.cmd(`agn ${title} ${body}`);
    }

    /**
     * Add an edge linking two nodes referenced by the title
     *
     * @param {string} a source title node
     * @param {string} b destination title node
     */
    async addEdge(a: string, b: string) {
        await r2.cmd(`age ${a} ${b}`);
    }

    /**
     * Get an ascii art representation of the graph as a string
     *
     * @returns {string} the computed graph
     */
    async toString(): Promise<string> {
        return r2.cmd("agg");
    }
}

export async function main() {
    const g = new Graph();

    await g.addNode("hello", "World");
    await g.addNode("world", "Hello");
    await g.addNode("patata", "Hello");
    await g.addEdge("hello", "world");
    await g.addEdge("hello", "patata");
    await g.addEdge("world", "world");

    console.log(g);
}
await main();
