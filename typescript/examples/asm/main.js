let GInstruction = null;

export const main = function main (Instruction) {
	GInstruction = Instruction;

	if (typeof r2 !== 'undefined') {
		// entrypoint
		r2.cmd("-a x86");
		r2.cmd("-b 64");
		
		const a = new Assembler();
		a.asm("nop");
		a.asm("nop");
		a.asm("nop");
		console.log("hex: " + a.toString());
		console.log(r2.cmd('""pad ' + a.toString()));

		r2.cmd("-e cfg.bigendian=false");
		r2.cmd("-a riscv");
		r2.cmd("-b 32");
		r2.cmd("-e cfg.bigendian=true");
	}

	const p = new RiscvProgram();
	// p.setEndian(true); // big endian
	// p.setProgramCounter(0);
	// p.asm('lui x1, 0');
	p.lui(1, 0);
	p.lui(2, 10);
	p.lui(3, 1);
	p.label('repeat');
	// p.addi(1, 1, 3);
	p.lui(0, 1000);
	p.nop();
	p.nop();
	p.nop();
	p.nop();
	p.nop();
	p.bne(1, 2, 'repeat');
	if (typeof r2 !== 'undefined') {
		r2.cmd("wx " + p.toString());
		console.log(r2.cmd("pd 20"));
	} else {
		console.log(p.toString());
	}
}

function rvasm(s) {
	if (GInstruction === null) {
		return rasm2(s);
	}
	try {
		// 'lui x17, 116088');
		var inst = new GInstruction.Instruction(s);
		return inst.hex;
	} catch (e) {
		console.error(e);
		return "____";
	}
}

function rasm2(s) {
	if (typeof r2 === "undefined") {
		console.error("Requires r2");
		return "____";
	}
	var hex = r2.cmd('""pa ' + s).trim();
	if (hex.length > 0) {
		return hex;
	}
	console.error("Invalid instruction: " + s);
	return "____";
}

class RiscvProgram {
	#program = "";
	#labels = {};
	#endian = false;
	#pc = 0;
	constructor() {
		this.#program = '';
		this.#labels = {};
	}
	setProgramCounter(pc) {
		this.#pc = pc;
	}
	setEndian(big) {
		this.#endian = big;
	}
	toString() {
		return this.#program;
	}
	append(x) {
		// reverse endian!!
		if (!this.#endian) {
			x = x.match(/.{2}/g).reverse().join('');
		}
		this.#pc += x.length / 2;
		this.#program += x;
	}

	// api
	label(s) {
		const pos = this.#pc; // this.#program.length / 4;
		this.#labels[s] = this.#pc;
		return pos;
	}
	asm(s) {
		const hex = rvasm(s);
		append(hex);
	}
	lui(rd, imm) {
		const islab = this.#labels[imm];
		const arg = islab? islab: imm;
		const hex = rvasm(`lui x${rd}, ${arg}`);
		this.append(hex);
	}
	addi(rd, rs1, rs2) {
		const hex = rvasm(`addi x${rd}, x${rs1}, x${rs2}`);
		this.append(hex);
	}
	beq(rs1, rs2, imm) {
		const arg = this.relative(imm);
		const hex = rvasm(`beq x${rs1}, x${rs2}, ${arg}`);
		this.append(hex);
	}
	bne(rs1, rs2, imm) {
		const arg = this.relative(imm);
		const hex = rvasm(`bne x${rs1}, x${rs2}, ${arg}`);
		this.append(hex);
	}
	nop() {
		this.addi(0,0,0);
	}
	relative(imm) {
		const islab = this.#labels[imm];
		const arg = islab? islab: imm;
		const delta = arg - this.#pc;
		return delta;
	}
}

class Assembler {
	program = "";
	labels = {};
	endian = false;
	pc = 0;
	constructor() {
		this.program = '';
		this.labels = {};
	}
	setProgramCounter(pc) {
		this.pc = pc;
	}
	setEndian(big) {
		this.endian = big;
	}
	toString() {
		return this.program;
	}
	append(x) {
		// reverse endian!!
		if (!this.endian) {
			x = x.match(/.{2}/g).reverse().join('');
		}
		this.pc += x.length / 2;
		this.program += x;
	}
	// api
	label(s) {
		const pos = this.pc; // this.#program.length / 4;
		this.labels[s] = this.pc;
		return pos;
	}
	asm(s) {
		const hex = rasm2(s);
		this.append(hex);
	}
}

