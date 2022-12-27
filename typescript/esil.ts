import { R2Pipe } from "r2papi";

declare var r2: R2Pipe;

class EsilToken {
	label: string = "";
	comment: string = "";
	text: string = "";
	addr: number = 0;
	position: number = 0;
	  constructor(text: string, position: number) {
		  this.text = text;
		  this.position = position;
	  }
	  toString() : string {
		  return this.text;
	  }
}

type EsilNodeType = "number" | "flag" | "register" | "operation" | "none" | "block" | "goto" | "label";

class EsilNode {
	lhs: EsilNode; // left side
	rhs: EsilNode; // right side
	children: EsilNode[];
	token: EsilToken;
	type: EsilNodeType;
	constructor (token: EsilToken, type: EsilNodeType) {
		this.token = token;
		this.type = type;
		this.children = [];
	}
	setSides(lhs: EsilNode, rhs: EsilNode): void {
		this.lhs = lhs;
		this.rhs = rhs;
	}
	addChildren(ths: EsilNode, fhs: EsilNode): void {
		if (ths !== undefined) {
			this.children.push(ths);
		}
		if (fhs !== undefined) {
			this.children.push(fhs);
		}
	}
	toEsil() : string {
		if (this.lhs !== undefined && this.rhs !== undefined) {
			// XXX handle ?{ }{ }
			let left = this.lhs.toEsil();
			if (left !== "") {
				left += ",";
			}
			return `${this.rhs.toEsil()},${left}${this.token}`;
		}
		return this.token.text;
	}
	toString() : string {
		let str = "";
		if (this.token.label !== "") {
			str += this.token.label + ":\n";
		}
		if (this.token.addr !== 0) {
			// str += "//  @ " + this.token.addr + "\n";
		}
		if (this.token.comment !== "") {
			str += "/*" + this.token.comment + "*/\n";
		}
		if (this.token.toString() === "GOTO") {
			if (this.children.length > 0) {
				const children = this.children[0];
				str += "goto label_" + children.token.position + ";\n";
			} else {
				// console.log(JSON.stringify(this,null, 2));
				let pos = 0;
				str += `goto label_${pos};\n`;
			}
		}
		if (this.children.length > 0) {
			str += `  (if (${this.rhs})\n`;
			for (let children of this.children) {
				if (children !== null) {
					const x = children.toString();
					if (x != "") {
						str += `  ${x}\n`;
					}
				}
			}
			str += ")\n";
		}
		if (this.lhs !== undefined && this.rhs !== undefined) {
			return str + `    ( ${this.lhs} ${this.token} ${this.rhs} )`;
			// return str + `${this.lhs} ${this.token} ${this.rhs}`;
		}
		return str + this.token.toString();
	}
}

class EsilParser {
	r2: R2Pipe;
	stack: EsilNode[]; // must be a stack or a list.. to parse sub expressions we must reset
	nodes: EsilNode[];
	root: EsilNode;
	tokens: EsilToken[];
	cur: number = 0;

	constructor (r2: R2Pipe) {
		this.r2 = r2;
		this.cur = 0;
		this.stack = [];
		this.nodes = [];
		this.tokens = [];
		this.root = new EsilNode (new EsilToken("function", 0), "block");
	}
	toJSON() : string {
		if (this.stack.length > 0) {
			// return JSON.stringify (this.stack, null, 2);
			throw new Error("The ESIL stack is not empty");
		}
		return JSON.stringify (this.root, null, 2);
	}
	toEsil() : string {
		return this.nodes
			.map( (x) => x.toEsil())
			.join(',');
	}
	private optimizeFlags(node: EsilNode) {
		if (node.rhs !== undefined) {
			const addr0 = +node.rhs.toString();
			if (addr0 > 0) {
				const fname = r2.cmd(`fd.@ ${addr0}`).trim().split("\n")[0].trim();
				if (fname != "" && fname.indexOf("+") == -1) {
					node.rhs.token.text = fname;
				}
			}
		}
		for (let i = 0; i < node.children.length;i++) {
			if (node.children[i].rhs === undefined) {
				continue;
			}
			const addr : number = +node.children[i].rhs.toString();
			if (addr > 0) {
				const fname = r2.cmd(`fd.@ ${addr}`).trim().split("\n")[0].trim();
				if (fname != "" && fname.indexOf("+") == -1) {
					node.children[i].rhs.token.text = fname;
				}
			}
			this.optimizeFlags (node.children[i]);
		}
	}
	optimize(options: string) : void {
		if (options.indexOf("flag") != -1) {
			// optimize the flags
			this.optimizeFlags(this.root);
		}
	}
	toString() : string {
		return this.root.children
			.map( (x) => x.toString())
			.join(';\n');
	}
	reset() : void {
		this.nodes = [];
		this.stack = [];
		this.tokens = [];
		this.cur = 0;
		this.root = new EsilNode (new EsilToken("function", 0), "block");
	}
	parseRange(from: number, to: number) {
		let pos = from;
		while (pos < this.tokens.length && pos < to) {
			const token = this.peek(pos);
			if (!token) {
				// console.log("BREAK");
				break;
			}
			// console.log(pos, token);
			this.cur = pos;
			this.pushToken(token);
			pos = this.cur;
			pos++;
		}
		// console.log("done");
	}
	parse(expr: string, addr?: number) : void | never {
		const tokens = expr.trim().split(',').map( (x) => x.trim() );
		const from = this.tokens.length;
		for (let tok of tokens) {
			const token = new EsilToken(tok, this.tokens.length);
			if (addr !== undefined) {
				token.addr = addr;
			}
			this.tokens.push(token);
		}
		const to = this.tokens.length;
		this.parseRange (from, to);
	}

	peek (a:number): EsilToken | undefined {
		return this.tokens[a];
	}

	pushToken(tok: EsilToken) : void | never {
		if (this.isNumber (tok)) {
			const node = new EsilNode(tok, "number");
			this.stack.push(node);
			this.nodes.push(node);
		} else if (this.isInternal (tok)) {
			const node = new EsilNode(tok, "flag");
			this.stack.push(node);
			this.nodes.push(node);
		} else if (this.isOperation (tok)) {
			// run the operation login
		} else {
			// assume it's a register, so just push the string
			const node = new EsilNode(tok, "register");
			this.stack.push(node);
			this.nodes.push(node);
		}
		// we need a list of register names to do this check properly
		// throw new Error ("Unknown token");
	}
	private isNumber(expr: EsilToken) : boolean {
		if (expr.toString().startsWith("0")) {
			return true;
		}
		return +expr > 0;
	}
	private isInternal(expr: EsilToken) : boolean {
		const text = expr.toString();
		return text && text.startsWith("$") && text.length > 1;
	}
	private parseUntil(start: number) : EsilNode | null {
		const from = start + 1;
		let pos = from;
		const origStack = [];
		const this_nodes_length = this.nodes.length;
		this.stack.forEach((x) => origStack.push(x));
		while (pos < this.tokens.length) {
			const token = this.peek(pos);
			if (!token) {
				break;
			}
			if (token.toString() === '}') {
				break;
			}
			if (token.toString() === '}{') {
				// return token;
				break;
			}
			// console.log("peek ", this.tokens[pos]);
			pos++;
		}
		this.stack = origStack;
		const to = pos;
		this.parseRange(from, to);
		const same = this.nodes.length == this_nodes_length;
		// console.log("BLOCK ("+ ep.toString());
		if (same) {
			return null;
		}
		return this.nodes[this.nodes.length - 1]; // this.tokens.length - 1];
	}
	private getNodeFor(index:number): null | EsilNode {
		const tok = this.peek(index);
		if (tok === undefined) {
			return null;
		}
		for (let node of this.nodes) {
			if (node.token.position === index) {
				return node;
			}
		}
		this.nodes.push(new EsilNode(new EsilToken("label", index), "label"));
		return null;
	}
	private findNodeFor(index:number): null | EsilNode {
		for (let node of this.nodes) {
			if (node.token.position === index) {
				return node;
			}
		}
		return null;
	}
	private isOperation(expr: EsilToken) : never | boolean {
		switch(expr.toString()) {
			// 1pop1push
			case "[1]":
			case "[2]":
			case "[4]":
			case "[8]":
				if (this.stack.length >= 1) {
					const i1 = this.stack.pop()!;
					// TODO: MemoryReferenceNode(i1));
					const mn = new EsilNode(i1.token, "operation"); // expr.toString());
					this.stack.push(i1); // mn);
				} else {
					throw new Error("Stack needs more items");
				}
				return true;
			// 1pop1push
			case "!":
				if (this.stack.length >= 1) {
					const i0 = new EsilNode(new EsilToken("", expr.position), "none");
					const i1 = this.stack.pop()!;
					const nn = new EsilNode(expr, "operation");
					nn.setSides(i0, i1);
					this.stack.push(nn);
				} else {
					throw new Error("Stack needs more items");
				}
				return true;
			case "":
			case "}":
			case "}{":
				// no pops or nothing, just does nothing
				return true;
			case "DUP":
				if (true) {
					if (this.stack.length < 1) {
						throw new Error("goto cant pop");
					}
					const destNode = this.stack.pop();
					this.stack.push(destNode);
					this.stack.push(destNode);
				}
				return true;
			case "GOTO":
				// take previous statement which should be const and add a label
				const prev = this.peek(expr.position - 1);
				if (prev !== null) {
					// TODO: check stack
					if (this.stack.length < 1) {
						throw new Error("goto cant pop");
					}
					const destNode = this.stack.pop();
					if (destNode !== null) {
						const value : number = 0 | +destNode.toString();
						if (value > 0) {
							const destToken = this.peek(value);
							if (destToken !== null) {
								destToken.label = "label_" + value;
								destToken.comment = "hehe";
								const nn = new EsilNode(expr, "goto");
								const gn = this.getNodeFor(destToken.position);
								if (gn != null) {
									nn.children.push(gn);
								}
								this.root.children.push(nn);
							} else {
								console.error("Cannot find goto node");
							}
						} else {
							console.error("Cannot find dest node for goto");
						}
					}
				}
				return true;
			// controlflow
			case "?{": // ESIL_TOKEN_IF
				if (this.stack.length >= 1) {
					const i0 = new EsilNode(new EsilToken("if", expr.position), "none");
					const i1 = this.stack.pop()!;
					const nn = new EsilNode(expr, "operation");
					nn.setSides(i0, i1); // left side can be ignored for now.. but we can express this somehow
					let trueBlock = this.parseUntil(expr.position);
					let falseBlock = null;
					// nn.addChildren(trueBlock, falseBlock);
					if (trueBlock !== null) {
						nn.children.push(trueBlock);
						this.nodes.push(trueBlock);
						falseBlock = this.parseUntil(trueBlock.token.position + 1);
						if (falseBlock !== null) {
							nn.children.push(falseBlock);
							this.nodes.push(falseBlock);
						}
					}
					// console.log("true", trueBlock);
					// console.log("false", falseBlock);
					// this.stack.push(nn);
					this.nodes.push(nn);
					this.root.children.push(nn);
					if (falseBlock !== null) {
						this.cur = falseBlock.token.position;
					}
				} else {
					throw new Error("Stack needs more items");
				}
				return true;
			case "-":
				if (this.stack.length >= 2) {
					const i0 = this.stack.pop()!;
					const i1 = this.stack.pop()!;
					const nn = new EsilNode(expr, "operation");
					nn.setSides(i0, i1);
					if (this.stack.length === 0) {
					//	this.root.children.push(nn);
					}
					this.stack.push(nn);
					this.nodes.push(nn);
				} else {
					throw new Error("Stack needs more items");
				}
				return true;
			// 2pop1push
			case "<":
			case ">":
			case "^":
			case "&":
			case "|":
			case "+":
			case "*":
			case "/":
			case ">>=":
			case "<<=":
			case ">>>=":
			case "<<<=":
			case ">>>>=":
			case "<<<<=":
				if (this.stack.length >= 2) {
					const i0 = this.stack.pop()!;
					const i1 = this.stack.pop()!;
					const nn = new EsilNode(expr, "operation");
					nn.setSides(i0, i1);
					if (this.stack.length === 0) {
					//	this.root.children.push(nn);
					}
					this.stack.push(nn);
					this.nodes.push(nn);
				} else {
					throw new Error("Stack needs more items");
				}
				return true;
			// 2pop0push
			case "=":
			case ":=":
			case "-=":
			case "+=":
			case "==":
			case "=[1]":
			case "=[2]":
			case "=[4]":
			case "=[8]":
				if (this.stack.length >= 2) {
					const i0 = this.stack.pop()!;
					const i1 = this.stack.pop()!;
					const nn = new EsilNode(expr, "operation");
					nn.setSides(i0, i1);
					if (this.stack.length === 0) {
						this.root.children.push(nn);
					}
					this.nodes.push(nn);
				} else {
					throw new Error("Stack needs more items");
				}
				return true;
		}
		return false;
	}
}

const ep = new EsilParser(r2);

/*
testComplex();
testBasic();
testConditional();
testLoop();
*/

function testLoop() {
	ep.parse("rax,rbx,:=,1,GOTO");
}

function testBasic() {
	ep.parse("1,rax,=");
	ep.parse("1,3,+,rax,:=");
	ep.parse("1,3,+,!,rax,:=");
}
function testComplex() {
	ep.parse("1,rax,=,1,3,+,rax,:=,1,3,+,!,rax,:=");
	ep.parse("cf,!,zf,|,?{,x16,}{,xzr,},x16,=");
}
function testConditional() {
//	ep.parse("1,?{,x0,}{,x1,},:=");
	ep.parse("zf,!,nf,vf,^,!,&,?{,4294982284,pc,:=,}");
}
/*
console.log(ep.toString());
console.log("---");
console.log(ep.toEsil());
*/
function pdq(arg:string) {
	let n = 0;
	switch (arg[0]) {
	case " ":
		n = +arg;
		break;
	case "f":
		const func = r2.cmdj("pdrj");
		for (let bb of func.bbs) {
			console.log("bb_" + bb.addr + ":");
			parseAmount (bb.ops.length);
		}
		break;
	case "e":
		ep.reset ();
		ep.parse(arg.slice(1).trim(), +r2.cmd("?v $$"));
		console.log(ep.toString());
		return;
	case "?":
		console.log("Usage: pdq[ef?] [ninstr] - quick decompiler plugin");
		console.log("pdq           - decompile 1 instruction");
		console.log("pdq 100       - decompile 100 instructions");
		console.log("pdqe 1,rax,:= - decompile given esil expressoin");
		console.log("pdqf          - decompile the current function");
		return;
	}
	if (n < 1) {
		n = 1;
	}
	parseAmount (n);
}

function parseAmount(n:number):void {
	ep.reset();
	// console.log("PDQ "+n);
	const lines = r2.cmd("pie "+n+" @e:scr.color=0").trim().split("\n");
	for (const line of lines) {
		const kv = line.split(' ');
		if (kv.length > 1) { // line != "") {
			// console.log("// @ " + kv[0]);
			ep.reset ();
			ep.parse(kv[1], +kv[0]);
			ep.optimize("flags");
			console.log(ep.toString());
		}
	}
	//console.log(ep.toString());
}

declare var r2plugin: any;
r2plugin("core", function() {
	function coreCall(cmd: string) {
		if (cmd.startsWith("pdq")) {
			try {
				pdq(cmd.slice(3));
			} catch (e) {
				console.error(e);
				e.printStackTrace();
			}
			return true;
		}
		return false;
	}
	return {
		"name": "pdq",
		"desc": "quick decompiler",
		"call": coreCall,
	}
});
