import { R2Pipe } from "r2papi";

declare var r2: R2Pipe;

type EsilToken = "+" | "-" | "*" | ":=" | string;

type EsilNodeType = "number" | "register" | "operation";

class EsilNode {
	position: number;
	lhs: EsilNode;
	rhs: EsilNode;
	token: string;
	type: EsilNodeType;
	constructor (token: string, type: EsilNodeType) {
		this.token = token;
		this.type = type;
	}
	setSides(lhs: EsilNode, rhs: EsilNode): void {
		this.lhs = lhs;
		this.rhs = rhs;
	}
	toString() : string {
		if (this.lhs !== undefined && this.rhs !== undefined) {
			return `${this.lhs} ${this.token} ${this.rhs}`;
		}
		return this.token;
	}
}

class EsilParser {
	r2: R2Pipe;
	stack: EsilNode[];
	nodes: EsilNode[];

	constructor (r2: R2Pipe) {
		this.r2 = r2;
		this.stack = [];
		this.nodes = [];
	}
	toJSON() : string {
		if (this.stack.length > 0) {
			// return JSON.stringify (this.stack, null, 2);
			throw new Error("The ESIL stack is not empty");
		}
		return JSON.stringify (this.nodes, null, 2);
	}
	toString() :string {
		return this.nodes
			.map( (x) => x.toString())
			.join('\n');
	}
	parse(expr: string) : void | never {
		const tokens = expr.trim().split(',');
		for (let tok of tokens) {
			this.push(tok);
		}
	}
	push(tok: EsilToken) : void | never {
		if (this.isNumber (tok)) {
			this.stack.push(new EsilNode(tok, "number"));
		} else if (this.isOperation (tok)) {
			// run the operation login
		} else {
			// assume it's a register, so just push the string
			this.stack.push(new EsilNode(tok, "register"));
		}
		// we need a list of register names to do this check properly
		// throw new Error ("Unknown token");
	}
	private isNumber(expr: string) : boolean {
		if (expr.startsWith("0")) {
			return true;
		}
		return +expr > 0;
	}
	private isOperation(expr: string) : boolean {
		switch(expr) {
			case "+": // 2pop1push
				if (this.stack.length >= 2) {
					const i0 = this.stack.pop()!;
					const i1 = this.stack.pop()!;
					const nn = new EsilNode(expr, "operation");
					nn.setSides(i0, i1);
					this.stack.push(nn);
				} else {
					throw new Error("Stack needs more items");
				}
				return true;
			case ":=": // 2pop0push
				if (this.stack.length >= 2) {
					const i0 = this.stack.pop()!;
					const i1 = this.stack.pop()!;
					const nn = new EsilNode(expr, "operation");
					nn.setSides(i0, i1);
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
ep.parse("1,3,+,rax,:=");
console.log(ep.toString());
