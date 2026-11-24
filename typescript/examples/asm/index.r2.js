📦
88 /index.js
11 /index.d.ts
46 /main.d.ts
2899 /main.js
606 /rvcodecjs/core/Config.d.ts
510 /rvcodecjs/core/Config.js
86413 /rvcodecjs/core/Constants.d.ts
45855 /rvcodecjs/core/Constants.js
894 /rvcodecjs/core/Decoder.d.ts
28479 /rvcodecjs/core/Decoder.js
534 /rvcodecjs/core/Encoder.d.ts
12707 /rvcodecjs/core/Encoder.js
1951 /rvcodecjs/core/Instruction.d.ts
2170 /rvcodecjs/core/Instruction.js
✄
import{main as o}from"./main.js";import*as r from"./rvcodecjs/core/Instruction.js";o(r);
✄
export {};

✄
export function main(Instruction: any): void;

✄
var t,e,n,r,i=this&&this.__classPrivateFieldSet||function(t,e,n,r,i){if("m"===r)throw new TypeError("Private method is not writable");if("a"===r&&!i)throw new TypeError("Private accessor was defined without a setter");if("function"==typeof e?t!==e||!i:!e.has(t))throw new TypeError("Cannot write private member to an object whose class did not declare it");return"a"===r?i.call(t,n):i?i.value=n:e.set(t,n),n},s=this&&this.__classPrivateFieldGet||function(t,e,n,r){if("a"===n&&!r)throw new TypeError("Private accessor was defined without a getter");if("function"==typeof e?t!==e||!r:!e.has(t))throw new TypeError("Cannot read private member from an object whose class did not declare it");return"m"===n?r:"a"===n?r.call(t):r?r.value:e.get(t)};let o=null;export const main=function(t){if(o=t,"undefined"!=typeof r2){r2.cmd("-a x86"),r2.cmd("-b 64");const t=new l;t.asm("nop"),t.asm("nop"),t.asm("nop"),console.log("hex: "+t.toString()),console.log(r2.cmd('""pad '+t.toString())),r2.cmd("-e cfg.bigendian=false"),r2.cmd("-a riscv"),r2.cmd("-b 32"),r2.cmd("-e cfg.bigendian=true")}const e=new h;e.lui(1,0),e.lui(2,10),e.lui(3,1),e.label("repeat"),e.lui(0,1e3),e.nop(),e.nop(),e.nop(),e.nop(),e.nop(),e.bne(1,2,"repeat"),"undefined"!=typeof r2?(r2.cmd("wx "+e.toString()),console.log(r2.cmd("pd 20"))):console.log(e.toString())};function a(t){if(null===o)return c(t);try{return new o.Instruction(t).hex}catch(t){return console.error(t),"____"}}function c(t){if("undefined"==typeof r2)return console.error("Requires r2"),"____";var e=r2.cmd('""pa '+t).trim();return e.length>0?e:(console.error("Invalid instruction: "+t),"____")}class h{constructor(){t.set(this,""),e.set(this,{}),n.set(this,!1),r.set(this,0),i(this,t,"","f"),i(this,e,{},"f")}setProgramCounter(t){i(this,r,t,"f")}setEndian(t){i(this,n,t,"f")}toString(){return s(this,t,"f")}append(e){s(this,n,"f")||(e=e.match(/.{2}/g).reverse().join("")),i(this,r,s(this,r,"f")+e.length/2,"f"),i(this,t,s(this,t,"f")+e,"f")}label(t){const n=s(this,r,"f");return s(this,e,"f")[t]=s(this,r,"f"),n}asm(t){const e=a(t);append(e)}lui(t,n){const r=s(this,e,"f")[n],i=a(`lui x${t}, ${r||n}`);this.append(i)}addi(t,e,n){const r=a(`addi x${t}, x${e}, x${n}`);this.append(r)}beq(t,e,n){const r=a(`beq x${t}, x${e}, ${this.relative(n)}`);this.append(r)}bne(t,e,n){const r=a(`bne x${t}, x${e}, ${this.relative(n)}`);this.append(r)}nop(){this.addi(0,0,0)}relative(t){const n=s(this,e,"f")[t];return(n||t)-s(this,r,"f")}}t=new WeakMap,e=new WeakMap,n=new WeakMap,r=new WeakMap;class l{constructor(){this.program="",this.labels={},this.endian=!1,this.pc=0,this.program="",this.labels={}}setProgramCounter(t){this.pc=t}setEndian(t){this.endian=t}toString(){return this.program}append(t){this.endian||(t=t.match(/.{2}/g).reverse().join("")),this.pc+=t.length/2,this.program+=t}label(t){const e=this.pc;return this.labels[t]=this.pc,e}asm(t){const e=c(t);this.append(e)}}
✄
export const CONFIG_TYPE: any;
export const COPTS_ISA: any;
export namespace configFields {
    namespace ISA {
        const name: string;
        const type: any;
        const opts: any[];
    }
    namespace ABI {
        const name_1: string;
        export { name_1 as name };
        const type_1: any;
        export { type_1 as type };
        const _default: boolean;
        export { _default as default };
    }
}
/**
 * Default configuration
 * - if no default defined, then constructed
 *   from the first option in `opts`
 */
export const configDefault: Readonly<{
    [k: string]: any;
}>;

✄
function e(e){return Object.freeze(e.reduce(((e,t)=>(e[t]=Symbol(t),e)),{}))}export const CONFIG_TYPE=e(["BOOL","CHOOSE_ONE"]);export const COPTS_ISA=e(["AUTO","RV32I","RV64I","RV128I"]);export const configFields={ISA:{name:"ISA",type:CONFIG_TYPE.CHOOSE_ONE,opts:Object.values(COPTS_ISA)},ABI:{name:"ABI",type:CONFIG_TYPE.BOOL,default:!1}};export const configDefault=Object.freeze(Object.fromEntries(Object.entries(configFields).map((([e,t])=>{var O;return[e,null!==(O=t.default)&&void 0!==O?O:t.opts[0]]}))));
✄
export namespace BASE {
    const bin: number;
    const dec: number;
    const hex: number;
}
export namespace XLEN {
    const rv32: number;
    const rv64: number;
    const rv128: number;
}
export namespace XLEN_MASK {
    const rv32_1: number;
    export { rv32_1 as rv32 };
    const rv64_1: number;
    export { rv64_1 as rv64 };
    const rv128_1: number;
    export { rv128_1 as rv128 };
    export const all: number;
}
export namespace FP_WIDTH {
    const S: string;
    const D: string;
    const Q: string;
}
export namespace FP_FMT {
    const S_1: string;
    export { S_1 as S };
    const D_1: string;
    export { D_1 as D };
    const Q_1: string;
    export { Q_1 as Q };
}
export namespace FIELDS {
    namespace opcode {
        const pos: number[];
        const name: string;
    }
    namespace rd {
        const pos_1: number[];
        export { pos_1 as pos };
        const name_1: string;
        export { name_1 as name };
    }
    namespace funct3 {
        const pos_2: number[];
        export { pos_2 as pos };
        const name_2: string;
        export { name_2 as name };
    }
    namespace rs1 {
        const pos_3: number[];
        export { pos_3 as pos };
        const name_3: string;
        export { name_3 as name };
    }
    namespace rs2 {
        const pos_4: number[];
        export { pos_4 as pos };
        const name_4: string;
        export { name_4 as name };
    }
    namespace r_funct5 {
        const pos_5: number[];
        export { pos_5 as pos };
        const name_5: string;
        export { name_5 as name };
    }
    namespace r_funct7 {
        const pos_6: number[];
        export { pos_6 as pos };
        const name_6: string;
        export { name_6 as name };
    }
    namespace r_aq {
        const pos_7: number[];
        export { pos_7 as pos };
        const name_7: string;
        export { name_7 as name };
    }
    namespace r_rl {
        const pos_8: number[];
        export { pos_8 as pos };
        const name_8: string;
        export { name_8 as name };
    }
    namespace r_fp_fmt {
        const pos_9: number[];
        export { pos_9 as pos };
        const name_9: string;
        export { name_9 as name };
    }
    namespace i_imm_11_0 {
        const pos_10: number[];
        export { pos_10 as pos };
        const name_10: string;
        export { name_10 as name };
    }
    namespace i_shtyp_11_7 {
        const pos_11: number[];
        export { pos_11 as pos };
        const name_11: string;
        export { name_11 as name };
    }
    namespace i_shtyp_11_6 {
        const pos_12: number[];
        export { pos_12 as pos };
        const name_12: string;
        export { name_12 as name };
    }
    namespace i_shtyp_11_5 {
        const pos_13: number[];
        export { pos_13 as pos };
        const name_13: string;
        export { name_13 as name };
    }
    namespace i_shtyp {
        const pos_14: number[];
        export { pos_14 as pos };
        const name_14: string;
        export { name_14 as name };
    }
    namespace i_shamt_6 {
        const pos_15: number[];
        export { pos_15 as pos };
        const name_15: string;
        export { name_15 as name };
    }
    namespace i_shamt_6_0 {
        const pos_16: number[];
        export { pos_16 as pos };
        const name_16: string;
        export { name_16 as name };
    }
    namespace i_shamt_5 {
        const pos_17: number[];
        export { pos_17 as pos };
        const name_17: string;
        export { name_17 as name };
    }
    namespace i_shamt_5_0 {
        const pos_18: number[];
        export { pos_18 as pos };
        const name_18: string;
        export { name_18 as name };
    }
    namespace i_shamt {
        const pos_19: number[];
        export { pos_19 as pos };
        const name_19: string;
        export { name_19 as name };
    }
    namespace i_funct12 {
        const pos_20: number[];
        export { pos_20 as pos };
        const name_20: string;
        export { name_20 as name };
    }
    namespace i_csr {
        const pos_21: number[];
        export { pos_21 as pos };
        const name_21: string;
        export { name_21 as name };
    }
    namespace i_imm_4_0 {
        const pos_22: number[];
        export { pos_22 as pos };
        const name_22: string;
        export { name_22 as name };
    }
    namespace i_fm {
        const pos_23: number[];
        export { pos_23 as pos };
        const name_23: string;
        export { name_23 as name };
    }
    namespace i_pred {
        const pos_24: number[];
        export { pos_24 as pos };
        const name_24: string;
        export { name_24 as name };
    }
    namespace i_succ {
        const pos_25: number[];
        export { pos_25 as pos };
        const name_25: string;
        export { name_25 as name };
    }
    namespace s_imm_4_0 {
        const pos_26: number[];
        export { pos_26 as pos };
        const name_26: string;
        export { name_26 as name };
    }
    namespace s_imm_11_5 {
        const pos_27: number[];
        export { pos_27 as pos };
        const name_27: string;
        export { name_27 as name };
    }
    namespace b_imm_4_1 {
        const pos_28: number[];
        export { pos_28 as pos };
        const name_28: string;
        export { name_28 as name };
    }
    namespace b_imm_11 {
        const pos_29: number[];
        export { pos_29 as pos };
        const name_29: string;
        export { name_29 as name };
    }
    namespace b_imm_10_5 {
        const pos_30: number[];
        export { pos_30 as pos };
        const name_30: string;
        export { name_30 as name };
    }
    namespace b_imm_12 {
        const pos_31: number[];
        export { pos_31 as pos };
        const name_31: string;
        export { name_31 as name };
    }
    namespace u_imm_31_12 {
        const pos_32: number[];
        export { pos_32 as pos };
        const name_32: string;
        export { name_32 as name };
    }
    namespace j_imm_20 {
        const pos_33: number[];
        export { pos_33 as pos };
        const name_33: string;
        export { name_33 as name };
    }
    namespace j_imm_10_1 {
        const pos_34: number[];
        export { pos_34 as pos };
        const name_34: string;
        export { name_34 as name };
    }
    namespace j_imm_11 {
        const pos_35: number[];
        export { pos_35 as pos };
        const name_35: string;
        export { name_35 as name };
    }
    namespace j_imm_19_12 {
        const pos_36: number[];
        export { pos_36 as pos };
        const name_36: string;
        export { name_36 as name };
    }
    namespace c_opcode {
        const pos_37: number[];
        export { pos_37 as pos };
        const name_37: string;
        export { name_37 as name };
    }
    namespace c_funct6 {
        const pos_38: number[];
        export { pos_38 as pos };
        const name_38: string;
        export { name_38 as name };
    }
    namespace c_funct4 {
        const pos_39: number[];
        export { pos_39 as pos };
        const name_39: string;
        export { name_39 as name };
    }
    namespace c_funct3 {
        const pos_40: number[];
        export { pos_40 as pos };
        const name_40: string;
        export { name_40 as name };
    }
    namespace c_funct2 {
        const pos_41: number[];
        export { pos_41 as pos };
        const name_41: string;
        export { name_41 as name };
    }
    namespace c_funct2_cb {
        const pos_42: number[];
        export { pos_42 as pos };
        const name_42: string;
        export { name_42 as name };
    }
    namespace c_rd {
        const pos_43: number[];
        export { pos_43 as pos };
        const name_43: string;
        export { name_43 as name };
    }
    namespace c_rs1 {
        const pos_44: number[];
        export { pos_44 as pos };
        const name_44: string;
        export { name_44 as name };
    }
    namespace c_rd_rs1 {
        const pos_45: number[];
        export { pos_45 as pos };
        const name_45: string;
        export { name_45 as name };
    }
    namespace c_rs2 {
        const pos_46: number[];
        export { pos_46 as pos };
        const name_46: string;
        export { name_46 as name };
    }
    namespace c_rd_prime {
        const pos_47: number[];
        export { pos_47 as pos };
        const name_47: string;
        export { name_47 as name };
    }
    namespace c_rs2_prime {
        const pos_48: number[];
        export { pos_48 as pos };
        const name_48: string;
        export { name_48 as name };
    }
    namespace c_rs1_prime {
        const pos_49: number[];
        export { pos_49 as pos };
        const name_49: string;
        export { name_49 as name };
    }
    namespace c_rd_rs1_prime {
        const pos_50: number[];
        export { pos_50 as pos };
        const name_50: string;
        export { name_50 as name };
    }
    namespace c_imm_ci_0 {
        const pos_51: number[];
        export { pos_51 as pos };
        const name_51: string;
        export { name_51 as name };
    }
    namespace c_imm_ci_1 {
        const pos_52: number[];
        export { pos_52 as pos };
        const name_52: string;
        export { name_52 as name };
    }
    namespace c_imm_css {
        const pos_53: number[];
        export { pos_53 as pos };
        const name_53: string;
        export { name_53 as name };
    }
    namespace c_imm_ciw {
        const pos_54: number[];
        export { pos_54 as pos };
        const name_54: string;
        export { name_54 as name };
    }
    namespace c_imm_cl_0 {
        const pos_55: number[];
        export { pos_55 as pos };
        const name_55: string;
        export { name_55 as name };
    }
    namespace c_imm_cl_1 {
        const pos_56: number[];
        export { pos_56 as pos };
        const name_56: string;
        export { name_56 as name };
    }
    namespace c_imm_cs_0 {
        const pos_57: number[];
        export { pos_57 as pos };
        const name_57: string;
        export { name_57 as name };
    }
    namespace c_imm_cs_1 {
        const pos_58: number[];
        export { pos_58 as pos };
        const name_58: string;
        export { name_58 as name };
    }
    namespace c_imm_cb_0 {
        const pos_59: number[];
        export { pos_59 as pos };
        const name_59: string;
        export { name_59 as name };
    }
    namespace c_imm_cb_1 {
        const pos_60: number[];
        export { pos_60 as pos };
        const name_60: string;
        export { name_60 as name };
    }
    namespace c_imm_cj {
        const pos_61: number[];
        export { pos_61 as pos };
        const name_61: string;
        export { name_61 as name };
    }
    namespace c_shamt_0 {
        const pos_62: number[];
        export { pos_62 as pos };
        const name_62: string;
        export { name_62 as name };
    }
    namespace c_shamt_1 {
        const pos_63: number[];
        export { pos_63 as pos };
        const name_63: string;
        export { name_63 as name };
    }
}
export namespace OPCODE {
    const LOAD: string;
    const LOAD_FP: string;
    const MISC_MEM: string;
    const OP_IMM: string;
    const AUIPC: string;
    const OP_IMM_32: string;
    const STORE: string;
    const STORE_FP: string;
    const AMO: string;
    const OP: string;
    const OP_32: string;
    const LUI: string;
    const MADD: string;
    const MSUB: string;
    const NMSUB: string;
    const NMADD: string;
    const OP_FP: string;
    const OP_IMM_64: string;
    const BRANCH: string;
    const JALR: string;
    const JAL: string;
    const SYSTEM: string;
    const OP_64: string;
}
export namespace C_OPCODE {
    const C0: string;
    const C1: string;
    const C2: string;
}
export namespace ISA_RV32I {
    namespace lui {
        export const isa: string;
        export const fmt: string;
        import opcode_1 = OPCODE.LUI;
        export { opcode_1 as opcode };
    }
    namespace auipc {
        const isa_1: string;
        export { isa_1 as isa };
        const fmt_1: string;
        export { fmt_1 as fmt };
        import opcode_2 = OPCODE.AUIPC;
        export { opcode_2 as opcode };
    }
    namespace jal {
        const isa_2: string;
        export { isa_2 as isa };
        const fmt_2: string;
        export { fmt_2 as fmt };
        import opcode_3 = OPCODE.JAL;
        export { opcode_3 as opcode };
    }
    namespace jalr {
        const isa_3: string;
        export { isa_3 as isa };
        const fmt_3: string;
        export { fmt_3 as fmt };
        const funct3_1: string;
        export { funct3_1 as funct3 };
        import opcode_4 = OPCODE.JALR;
        export { opcode_4 as opcode };
    }
    namespace beq {
        const isa_4: string;
        export { isa_4 as isa };
        const fmt_4: string;
        export { fmt_4 as fmt };
        const funct3_2: string;
        export { funct3_2 as funct3 };
        import opcode_5 = OPCODE.BRANCH;
        export { opcode_5 as opcode };
    }
    namespace bne {
        const isa_5: string;
        export { isa_5 as isa };
        const fmt_5: string;
        export { fmt_5 as fmt };
        const funct3_3: string;
        export { funct3_3 as funct3 };
        import opcode_6 = OPCODE.BRANCH;
        export { opcode_6 as opcode };
    }
    namespace blt {
        const isa_6: string;
        export { isa_6 as isa };
        const fmt_6: string;
        export { fmt_6 as fmt };
        const funct3_4: string;
        export { funct3_4 as funct3 };
        import opcode_7 = OPCODE.BRANCH;
        export { opcode_7 as opcode };
    }
    namespace bge {
        const isa_7: string;
        export { isa_7 as isa };
        const fmt_7: string;
        export { fmt_7 as fmt };
        const funct3_5: string;
        export { funct3_5 as funct3 };
        import opcode_8 = OPCODE.BRANCH;
        export { opcode_8 as opcode };
    }
    namespace bltu {
        const isa_8: string;
        export { isa_8 as isa };
        const fmt_8: string;
        export { fmt_8 as fmt };
        const funct3_6: string;
        export { funct3_6 as funct3 };
        import opcode_9 = OPCODE.BRANCH;
        export { opcode_9 as opcode };
    }
    namespace bgeu {
        const isa_9: string;
        export { isa_9 as isa };
        const fmt_9: string;
        export { fmt_9 as fmt };
        const funct3_7: string;
        export { funct3_7 as funct3 };
        import opcode_10 = OPCODE.BRANCH;
        export { opcode_10 as opcode };
    }
    namespace lb {
        const isa_10: string;
        export { isa_10 as isa };
        const fmt_10: string;
        export { fmt_10 as fmt };
        const funct3_8: string;
        export { funct3_8 as funct3 };
        import opcode_11 = OPCODE.LOAD;
        export { opcode_11 as opcode };
    }
    namespace lh {
        const isa_11: string;
        export { isa_11 as isa };
        const fmt_11: string;
        export { fmt_11 as fmt };
        const funct3_9: string;
        export { funct3_9 as funct3 };
        import opcode_12 = OPCODE.LOAD;
        export { opcode_12 as opcode };
    }
    namespace lw {
        const isa_12: string;
        export { isa_12 as isa };
        const fmt_12: string;
        export { fmt_12 as fmt };
        const funct3_10: string;
        export { funct3_10 as funct3 };
        import opcode_13 = OPCODE.LOAD;
        export { opcode_13 as opcode };
    }
    namespace lbu {
        const isa_13: string;
        export { isa_13 as isa };
        const fmt_13: string;
        export { fmt_13 as fmt };
        const funct3_11: string;
        export { funct3_11 as funct3 };
        import opcode_14 = OPCODE.LOAD;
        export { opcode_14 as opcode };
    }
    namespace lhu {
        const isa_14: string;
        export { isa_14 as isa };
        const fmt_14: string;
        export { fmt_14 as fmt };
        const funct3_12: string;
        export { funct3_12 as funct3 };
        import opcode_15 = OPCODE.LOAD;
        export { opcode_15 as opcode };
    }
    namespace sb {
        const isa_15: string;
        export { isa_15 as isa };
        const fmt_15: string;
        export { fmt_15 as fmt };
        const funct3_13: string;
        export { funct3_13 as funct3 };
        import opcode_16 = OPCODE.STORE;
        export { opcode_16 as opcode };
    }
    namespace sh {
        const isa_16: string;
        export { isa_16 as isa };
        const fmt_16: string;
        export { fmt_16 as fmt };
        const funct3_14: string;
        export { funct3_14 as funct3 };
        import opcode_17 = OPCODE.STORE;
        export { opcode_17 as opcode };
    }
    namespace sw {
        const isa_17: string;
        export { isa_17 as isa };
        const fmt_17: string;
        export { fmt_17 as fmt };
        const funct3_15: string;
        export { funct3_15 as funct3 };
        import opcode_18 = OPCODE.STORE;
        export { opcode_18 as opcode };
    }
    namespace addi {
        const isa_18: string;
        export { isa_18 as isa };
        const fmt_18: string;
        export { fmt_18 as fmt };
        const funct3_16: string;
        export { funct3_16 as funct3 };
        import opcode_19 = OPCODE.OP_IMM;
        export { opcode_19 as opcode };
    }
    namespace slti {
        const isa_19: string;
        export { isa_19 as isa };
        const fmt_19: string;
        export { fmt_19 as fmt };
        const funct3_17: string;
        export { funct3_17 as funct3 };
        import opcode_20 = OPCODE.OP_IMM;
        export { opcode_20 as opcode };
    }
    namespace sltiu {
        const isa_20: string;
        export { isa_20 as isa };
        const fmt_20: string;
        export { fmt_20 as fmt };
        const funct3_18: string;
        export { funct3_18 as funct3 };
        import opcode_21 = OPCODE.OP_IMM;
        export { opcode_21 as opcode };
    }
    namespace xori {
        const isa_21: string;
        export { isa_21 as isa };
        const fmt_21: string;
        export { fmt_21 as fmt };
        const funct3_19: string;
        export { funct3_19 as funct3 };
        import opcode_22 = OPCODE.OP_IMM;
        export { opcode_22 as opcode };
    }
    namespace ori {
        const isa_22: string;
        export { isa_22 as isa };
        const fmt_22: string;
        export { fmt_22 as fmt };
        const funct3_20: string;
        export { funct3_20 as funct3 };
        import opcode_23 = OPCODE.OP_IMM;
        export { opcode_23 as opcode };
    }
    namespace andi {
        const isa_23: string;
        export { isa_23 as isa };
        const fmt_23: string;
        export { fmt_23 as fmt };
        const funct3_21: string;
        export { funct3_21 as funct3 };
        import opcode_24 = OPCODE.OP_IMM;
        export { opcode_24 as opcode };
    }
    namespace slli {
        const isa_24: string;
        export { isa_24 as isa };
        const fmt_24: string;
        export { fmt_24 as fmt };
        export const shtyp: string;
        const funct3_22: string;
        export { funct3_22 as funct3 };
        import opcode_25 = OPCODE.OP_IMM;
        export { opcode_25 as opcode };
    }
    namespace srli {
        const isa_25: string;
        export { isa_25 as isa };
        const fmt_25: string;
        export { fmt_25 as fmt };
        const shtyp_1: string;
        export { shtyp_1 as shtyp };
        const funct3_23: string;
        export { funct3_23 as funct3 };
        import opcode_26 = OPCODE.OP_IMM;
        export { opcode_26 as opcode };
    }
    namespace srai {
        const isa_26: string;
        export { isa_26 as isa };
        const fmt_26: string;
        export { fmt_26 as fmt };
        const shtyp_2: string;
        export { shtyp_2 as shtyp };
        const funct3_24: string;
        export { funct3_24 as funct3 };
        import opcode_27 = OPCODE.OP_IMM;
        export { opcode_27 as opcode };
    }
    namespace add {
        const isa_27: string;
        export { isa_27 as isa };
        const fmt_27: string;
        export { fmt_27 as fmt };
        export const funct7: string;
        const funct3_25: string;
        export { funct3_25 as funct3 };
        import opcode_28 = OPCODE.OP;
        export { opcode_28 as opcode };
    }
    namespace sub {
        const isa_28: string;
        export { isa_28 as isa };
        const fmt_28: string;
        export { fmt_28 as fmt };
        const funct7_1: string;
        export { funct7_1 as funct7 };
        const funct3_26: string;
        export { funct3_26 as funct3 };
        import opcode_29 = OPCODE.OP;
        export { opcode_29 as opcode };
    }
    namespace sll {
        const isa_29: string;
        export { isa_29 as isa };
        const fmt_29: string;
        export { fmt_29 as fmt };
        const funct7_2: string;
        export { funct7_2 as funct7 };
        const funct3_27: string;
        export { funct3_27 as funct3 };
        import opcode_30 = OPCODE.OP;
        export { opcode_30 as opcode };
    }
    namespace slt {
        const isa_30: string;
        export { isa_30 as isa };
        const fmt_30: string;
        export { fmt_30 as fmt };
        const funct7_3: string;
        export { funct7_3 as funct7 };
        const funct3_28: string;
        export { funct3_28 as funct3 };
        import opcode_31 = OPCODE.OP;
        export { opcode_31 as opcode };
    }
    namespace sltu {
        const isa_31: string;
        export { isa_31 as isa };
        const fmt_31: string;
        export { fmt_31 as fmt };
        const funct7_4: string;
        export { funct7_4 as funct7 };
        const funct3_29: string;
        export { funct3_29 as funct3 };
        import opcode_32 = OPCODE.OP;
        export { opcode_32 as opcode };
    }
    namespace xor {
        const isa_32: string;
        export { isa_32 as isa };
        const fmt_32: string;
        export { fmt_32 as fmt };
        const funct7_5: string;
        export { funct7_5 as funct7 };
        const funct3_30: string;
        export { funct3_30 as funct3 };
        import opcode_33 = OPCODE.OP;
        export { opcode_33 as opcode };
    }
    namespace srl {
        const isa_33: string;
        export { isa_33 as isa };
        const fmt_33: string;
        export { fmt_33 as fmt };
        const funct7_6: string;
        export { funct7_6 as funct7 };
        const funct3_31: string;
        export { funct3_31 as funct3 };
        import opcode_34 = OPCODE.OP;
        export { opcode_34 as opcode };
    }
    namespace sra {
        const isa_34: string;
        export { isa_34 as isa };
        const fmt_34: string;
        export { fmt_34 as fmt };
        const funct7_7: string;
        export { funct7_7 as funct7 };
        const funct3_32: string;
        export { funct3_32 as funct3 };
        import opcode_35 = OPCODE.OP;
        export { opcode_35 as opcode };
    }
    namespace or {
        const isa_35: string;
        export { isa_35 as isa };
        const fmt_35: string;
        export { fmt_35 as fmt };
        const funct7_8: string;
        export { funct7_8 as funct7 };
        const funct3_33: string;
        export { funct3_33 as funct3 };
        import opcode_36 = OPCODE.OP;
        export { opcode_36 as opcode };
    }
    namespace and {
        const isa_36: string;
        export { isa_36 as isa };
        const fmt_36: string;
        export { fmt_36 as fmt };
        const funct7_9: string;
        export { funct7_9 as funct7 };
        const funct3_34: string;
        export { funct3_34 as funct3 };
        import opcode_37 = OPCODE.OP;
        export { opcode_37 as opcode };
    }
    namespace fence {
        const isa_37: string;
        export { isa_37 as isa };
        const fmt_37: string;
        export { fmt_37 as fmt };
        const funct3_35: string;
        export { funct3_35 as funct3 };
        import opcode_38 = OPCODE.MISC_MEM;
        export { opcode_38 as opcode };
    }
    namespace ecall {
        const isa_38: string;
        export { isa_38 as isa };
        const fmt_38: string;
        export { fmt_38 as fmt };
        export const funct12: string;
        const funct3_36: string;
        export { funct3_36 as funct3 };
        import opcode_39 = OPCODE.SYSTEM;
        export { opcode_39 as opcode };
    }
    namespace ebreak {
        const isa_39: string;
        export { isa_39 as isa };
        const fmt_39: string;
        export { fmt_39 as fmt };
        const funct12_1: string;
        export { funct12_1 as funct12 };
        const funct3_37: string;
        export { funct3_37 as funct3 };
        import opcode_40 = OPCODE.SYSTEM;
        export { opcode_40 as opcode };
    }
}
export namespace ISA_RV64I {
    namespace addiw {
        const isa_40: string;
        export { isa_40 as isa };
        const fmt_40: string;
        export { fmt_40 as fmt };
        const funct3_38: string;
        export { funct3_38 as funct3 };
        import opcode_41 = OPCODE.OP_IMM_32;
        export { opcode_41 as opcode };
    }
    namespace slliw {
        const isa_41: string;
        export { isa_41 as isa };
        const fmt_41: string;
        export { fmt_41 as fmt };
        const shtyp_3: string;
        export { shtyp_3 as shtyp };
        const funct3_39: string;
        export { funct3_39 as funct3 };
        import opcode_42 = OPCODE.OP_IMM_32;
        export { opcode_42 as opcode };
    }
    namespace srliw {
        const isa_42: string;
        export { isa_42 as isa };
        const fmt_42: string;
        export { fmt_42 as fmt };
        const shtyp_4: string;
        export { shtyp_4 as shtyp };
        const funct3_40: string;
        export { funct3_40 as funct3 };
        import opcode_43 = OPCODE.OP_IMM_32;
        export { opcode_43 as opcode };
    }
    namespace sraiw {
        const isa_43: string;
        export { isa_43 as isa };
        const fmt_43: string;
        export { fmt_43 as fmt };
        const shtyp_5: string;
        export { shtyp_5 as shtyp };
        const funct3_41: string;
        export { funct3_41 as funct3 };
        import opcode_44 = OPCODE.OP_IMM_32;
        export { opcode_44 as opcode };
    }
    namespace addw {
        const isa_44: string;
        export { isa_44 as isa };
        const fmt_44: string;
        export { fmt_44 as fmt };
        const funct7_10: string;
        export { funct7_10 as funct7 };
        const funct3_42: string;
        export { funct3_42 as funct3 };
        import opcode_45 = OPCODE.OP_32;
        export { opcode_45 as opcode };
    }
    namespace subw {
        const isa_45: string;
        export { isa_45 as isa };
        const fmt_45: string;
        export { fmt_45 as fmt };
        const funct7_11: string;
        export { funct7_11 as funct7 };
        const funct3_43: string;
        export { funct3_43 as funct3 };
        import opcode_46 = OPCODE.OP_32;
        export { opcode_46 as opcode };
    }
    namespace sllw {
        const isa_46: string;
        export { isa_46 as isa };
        const fmt_46: string;
        export { fmt_46 as fmt };
        const funct7_12: string;
        export { funct7_12 as funct7 };
        const funct3_44: string;
        export { funct3_44 as funct3 };
        import opcode_47 = OPCODE.OP_32;
        export { opcode_47 as opcode };
    }
    namespace srlw {
        const isa_47: string;
        export { isa_47 as isa };
        const fmt_47: string;
        export { fmt_47 as fmt };
        const funct7_13: string;
        export { funct7_13 as funct7 };
        const funct3_45: string;
        export { funct3_45 as funct3 };
        import opcode_48 = OPCODE.OP_32;
        export { opcode_48 as opcode };
    }
    namespace sraw {
        const isa_48: string;
        export { isa_48 as isa };
        const fmt_48: string;
        export { fmt_48 as fmt };
        const funct7_14: string;
        export { funct7_14 as funct7 };
        const funct3_46: string;
        export { funct3_46 as funct3 };
        import opcode_49 = OPCODE.OP_32;
        export { opcode_49 as opcode };
    }
    namespace ld {
        const isa_49: string;
        export { isa_49 as isa };
        const fmt_49: string;
        export { fmt_49 as fmt };
        const funct3_47: string;
        export { funct3_47 as funct3 };
        import opcode_50 = OPCODE.LOAD;
        export { opcode_50 as opcode };
    }
    namespace lwu {
        const isa_50: string;
        export { isa_50 as isa };
        const fmt_50: string;
        export { fmt_50 as fmt };
        const funct3_48: string;
        export { funct3_48 as funct3 };
        import opcode_51 = OPCODE.LOAD;
        export { opcode_51 as opcode };
    }
    namespace sd {
        const isa_51: string;
        export { isa_51 as isa };
        const fmt_51: string;
        export { fmt_51 as fmt };
        const funct3_49: string;
        export { funct3_49 as funct3 };
        import opcode_52 = OPCODE.STORE;
        export { opcode_52 as opcode };
    }
}
export namespace ISA_RV128I {
    namespace addid {
        const isa_52: string;
        export { isa_52 as isa };
        const fmt_52: string;
        export { fmt_52 as fmt };
        const funct3_50: string;
        export { funct3_50 as funct3 };
        import opcode_53 = OPCODE.OP_IMM_64;
        export { opcode_53 as opcode };
    }
    namespace sllid {
        const isa_53: string;
        export { isa_53 as isa };
        const fmt_53: string;
        export { fmt_53 as fmt };
        const shtyp_6: string;
        export { shtyp_6 as shtyp };
        const funct3_51: string;
        export { funct3_51 as funct3 };
        import opcode_54 = OPCODE.OP_IMM_64;
        export { opcode_54 as opcode };
    }
    namespace srlid {
        const isa_54: string;
        export { isa_54 as isa };
        const fmt_54: string;
        export { fmt_54 as fmt };
        const shtyp_7: string;
        export { shtyp_7 as shtyp };
        const funct3_52: string;
        export { funct3_52 as funct3 };
        import opcode_55 = OPCODE.OP_IMM_64;
        export { opcode_55 as opcode };
    }
    namespace sraid {
        const isa_55: string;
        export { isa_55 as isa };
        const fmt_55: string;
        export { fmt_55 as fmt };
        const shtyp_8: string;
        export { shtyp_8 as shtyp };
        const funct3_53: string;
        export { funct3_53 as funct3 };
        import opcode_56 = OPCODE.OP_IMM_64;
        export { opcode_56 as opcode };
    }
    namespace addd {
        const isa_56: string;
        export { isa_56 as isa };
        const fmt_56: string;
        export { fmt_56 as fmt };
        const funct7_15: string;
        export { funct7_15 as funct7 };
        const funct3_54: string;
        export { funct3_54 as funct3 };
        import opcode_57 = OPCODE.OP_64;
        export { opcode_57 as opcode };
    }
    namespace subd {
        const isa_57: string;
        export { isa_57 as isa };
        const fmt_57: string;
        export { fmt_57 as fmt };
        const funct7_16: string;
        export { funct7_16 as funct7 };
        const funct3_55: string;
        export { funct3_55 as funct3 };
        import opcode_58 = OPCODE.OP_64;
        export { opcode_58 as opcode };
    }
    namespace slld {
        const isa_58: string;
        export { isa_58 as isa };
        const fmt_58: string;
        export { fmt_58 as fmt };
        const funct7_17: string;
        export { funct7_17 as funct7 };
        const funct3_56: string;
        export { funct3_56 as funct3 };
        import opcode_59 = OPCODE.OP_64;
        export { opcode_59 as opcode };
    }
    namespace srld {
        const isa_59: string;
        export { isa_59 as isa };
        const fmt_59: string;
        export { fmt_59 as fmt };
        const funct7_18: string;
        export { funct7_18 as funct7 };
        const funct3_57: string;
        export { funct3_57 as funct3 };
        import opcode_60 = OPCODE.OP_64;
        export { opcode_60 as opcode };
    }
    namespace srad {
        const isa_60: string;
        export { isa_60 as isa };
        const fmt_60: string;
        export { fmt_60 as fmt };
        const funct7_19: string;
        export { funct7_19 as funct7 };
        const funct3_58: string;
        export { funct3_58 as funct3 };
        import opcode_61 = OPCODE.OP_64;
        export { opcode_61 as opcode };
    }
    namespace lq {
        const isa_61: string;
        export { isa_61 as isa };
        const fmt_61: string;
        export { fmt_61 as fmt };
        const funct3_59: string;
        export { funct3_59 as funct3 };
        import opcode_62 = OPCODE.MISC_MEM;
        export { opcode_62 as opcode };
    }
    namespace ldu {
        const isa_62: string;
        export { isa_62 as isa };
        const fmt_62: string;
        export { fmt_62 as fmt };
        const funct3_60: string;
        export { funct3_60 as funct3 };
        import opcode_63 = OPCODE.LOAD;
        export { opcode_63 as opcode };
    }
    namespace sq {
        const isa_63: string;
        export { isa_63 as isa };
        const fmt_63: string;
        export { fmt_63 as fmt };
        const funct3_61: string;
        export { funct3_61 as funct3 };
        import opcode_64 = OPCODE.STORE;
        export { opcode_64 as opcode };
    }
}
export const ISA_Zifencei: {
    'fence.i': {
        isa: string;
        fmt: string;
        funct3: string;
        opcode: string;
    };
};
export namespace ISA_Zicsr {
    namespace csrrw {
        const isa_64: string;
        export { isa_64 as isa };
        const fmt_64: string;
        export { fmt_64 as fmt };
        const funct3_62: string;
        export { funct3_62 as funct3 };
        import opcode_65 = OPCODE.SYSTEM;
        export { opcode_65 as opcode };
    }
    namespace csrrs {
        const isa_65: string;
        export { isa_65 as isa };
        const fmt_65: string;
        export { fmt_65 as fmt };
        const funct3_63: string;
        export { funct3_63 as funct3 };
        import opcode_66 = OPCODE.SYSTEM;
        export { opcode_66 as opcode };
    }
    namespace csrrc {
        const isa_66: string;
        export { isa_66 as isa };
        const fmt_66: string;
        export { fmt_66 as fmt };
        const funct3_64: string;
        export { funct3_64 as funct3 };
        import opcode_67 = OPCODE.SYSTEM;
        export { opcode_67 as opcode };
    }
    namespace csrrwi {
        const isa_67: string;
        export { isa_67 as isa };
        const fmt_67: string;
        export { fmt_67 as fmt };
        const funct3_65: string;
        export { funct3_65 as funct3 };
        import opcode_68 = OPCODE.SYSTEM;
        export { opcode_68 as opcode };
    }
    namespace csrrsi {
        const isa_68: string;
        export { isa_68 as isa };
        const fmt_68: string;
        export { fmt_68 as fmt };
        const funct3_66: string;
        export { funct3_66 as funct3 };
        import opcode_69 = OPCODE.SYSTEM;
        export { opcode_69 as opcode };
    }
    namespace csrrci {
        const isa_69: string;
        export { isa_69 as isa };
        const fmt_69: string;
        export { fmt_69 as fmt };
        const funct3_67: string;
        export { funct3_67 as funct3 };
        import opcode_70 = OPCODE.SYSTEM;
        export { opcode_70 as opcode };
    }
}
export namespace ISA_M {
    namespace mul {
        const isa_70: string;
        export { isa_70 as isa };
        const fmt_70: string;
        export { fmt_70 as fmt };
        const funct7_20: string;
        export { funct7_20 as funct7 };
        const funct3_68: string;
        export { funct3_68 as funct3 };
        import opcode_71 = OPCODE.OP;
        export { opcode_71 as opcode };
    }
    namespace mulh {
        const isa_71: string;
        export { isa_71 as isa };
        const fmt_71: string;
        export { fmt_71 as fmt };
        const funct7_21: string;
        export { funct7_21 as funct7 };
        const funct3_69: string;
        export { funct3_69 as funct3 };
        import opcode_72 = OPCODE.OP;
        export { opcode_72 as opcode };
    }
    namespace mulhsu {
        const isa_72: string;
        export { isa_72 as isa };
        const fmt_72: string;
        export { fmt_72 as fmt };
        const funct7_22: string;
        export { funct7_22 as funct7 };
        const funct3_70: string;
        export { funct3_70 as funct3 };
        import opcode_73 = OPCODE.OP;
        export { opcode_73 as opcode };
    }
    namespace mulhu {
        const isa_73: string;
        export { isa_73 as isa };
        const fmt_73: string;
        export { fmt_73 as fmt };
        const funct7_23: string;
        export { funct7_23 as funct7 };
        const funct3_71: string;
        export { funct3_71 as funct3 };
        import opcode_74 = OPCODE.OP;
        export { opcode_74 as opcode };
    }
    namespace div {
        const isa_74: string;
        export { isa_74 as isa };
        const fmt_74: string;
        export { fmt_74 as fmt };
        const funct7_24: string;
        export { funct7_24 as funct7 };
        const funct3_72: string;
        export { funct3_72 as funct3 };
        import opcode_75 = OPCODE.OP;
        export { opcode_75 as opcode };
    }
    namespace divu {
        const isa_75: string;
        export { isa_75 as isa };
        const fmt_75: string;
        export { fmt_75 as fmt };
        const funct7_25: string;
        export { funct7_25 as funct7 };
        const funct3_73: string;
        export { funct3_73 as funct3 };
        import opcode_76 = OPCODE.OP;
        export { opcode_76 as opcode };
    }
    namespace rem {
        const isa_76: string;
        export { isa_76 as isa };
        const fmt_76: string;
        export { fmt_76 as fmt };
        const funct7_26: string;
        export { funct7_26 as funct7 };
        const funct3_74: string;
        export { funct3_74 as funct3 };
        import opcode_77 = OPCODE.OP;
        export { opcode_77 as opcode };
    }
    namespace remu {
        const isa_77: string;
        export { isa_77 as isa };
        const fmt_77: string;
        export { fmt_77 as fmt };
        const funct7_27: string;
        export { funct7_27 as funct7 };
        const funct3_75: string;
        export { funct3_75 as funct3 };
        import opcode_78 = OPCODE.OP;
        export { opcode_78 as opcode };
    }
    namespace mulw {
        const isa_78: string;
        export { isa_78 as isa };
        const fmt_78: string;
        export { fmt_78 as fmt };
        const funct7_28: string;
        export { funct7_28 as funct7 };
        const funct3_76: string;
        export { funct3_76 as funct3 };
        import opcode_79 = OPCODE.OP_32;
        export { opcode_79 as opcode };
    }
    namespace divw {
        const isa_79: string;
        export { isa_79 as isa };
        const fmt_79: string;
        export { fmt_79 as fmt };
        const funct7_29: string;
        export { funct7_29 as funct7 };
        const funct3_77: string;
        export { funct3_77 as funct3 };
        import opcode_80 = OPCODE.OP_32;
        export { opcode_80 as opcode };
    }
    namespace divuw {
        const isa_80: string;
        export { isa_80 as isa };
        const fmt_80: string;
        export { fmt_80 as fmt };
        const funct7_30: string;
        export { funct7_30 as funct7 };
        const funct3_78: string;
        export { funct3_78 as funct3 };
        import opcode_81 = OPCODE.OP_32;
        export { opcode_81 as opcode };
    }
    namespace remw {
        const isa_81: string;
        export { isa_81 as isa };
        const fmt_81: string;
        export { fmt_81 as fmt };
        const funct7_31: string;
        export { funct7_31 as funct7 };
        const funct3_79: string;
        export { funct3_79 as funct3 };
        import opcode_82 = OPCODE.OP_32;
        export { opcode_82 as opcode };
    }
    namespace remuw {
        const isa_82: string;
        export { isa_82 as isa };
        const fmt_82: string;
        export { fmt_82 as fmt };
        const funct7_32: string;
        export { funct7_32 as funct7 };
        const funct3_80: string;
        export { funct3_80 as funct3 };
        import opcode_83 = OPCODE.OP_32;
        export { opcode_83 as opcode };
    }
    namespace muld {
        const isa_83: string;
        export { isa_83 as isa };
        const fmt_83: string;
        export { fmt_83 as fmt };
        const funct7_33: string;
        export { funct7_33 as funct7 };
        const funct3_81: string;
        export { funct3_81 as funct3 };
        import opcode_84 = OPCODE.OP_64;
        export { opcode_84 as opcode };
    }
    namespace divd {
        const isa_84: string;
        export { isa_84 as isa };
        const fmt_84: string;
        export { fmt_84 as fmt };
        const funct7_34: string;
        export { funct7_34 as funct7 };
        const funct3_82: string;
        export { funct3_82 as funct3 };
        import opcode_85 = OPCODE.OP_64;
        export { opcode_85 as opcode };
    }
    namespace divud {
        const isa_85: string;
        export { isa_85 as isa };
        const fmt_85: string;
        export { fmt_85 as fmt };
        const funct7_35: string;
        export { funct7_35 as funct7 };
        const funct3_83: string;
        export { funct3_83 as funct3 };
        import opcode_86 = OPCODE.OP_64;
        export { opcode_86 as opcode };
    }
    namespace remd {
        const isa_86: string;
        export { isa_86 as isa };
        const fmt_86: string;
        export { fmt_86 as fmt };
        const funct7_36: string;
        export { funct7_36 as funct7 };
        const funct3_84: string;
        export { funct3_84 as funct3 };
        import opcode_87 = OPCODE.OP_64;
        export { opcode_87 as opcode };
    }
    namespace remud {
        const isa_87: string;
        export { isa_87 as isa };
        const fmt_87: string;
        export { fmt_87 as fmt };
        const funct7_37: string;
        export { funct7_37 as funct7 };
        const funct3_85: string;
        export { funct3_85 as funct3 };
        import opcode_88 = OPCODE.OP_64;
        export { opcode_88 as opcode };
    }
}
export const ISA_A: {
    'lr.w': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'sc.w': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoswap.w': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoadd.w': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoxor.w': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoand.w': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoor.w': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amomin.w': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amomax.w': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amominu.w': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amomaxu.w': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'lr.d': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'sc.d': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoswap.d': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoadd.d': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoxor.d': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoand.d': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoor.d': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amomin.d': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amomax.d': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amominu.d': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amomaxu.d': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'lr.q': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'sc.q': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoswap.q': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoadd.q': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoxor.q': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoand.q': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amoor.q': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amomin.q': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amomax.q': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amominu.q': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
    'amomaxu.q': {
        isa: string;
        fmt: string;
        funct5: string;
        funct3: string;
        opcode: string;
    };
};
export const ISA_F: {
    flw: {
        isa: string;
        fmt: string;
        funct3: string;
        opcode: string;
    };
    fsw: {
        isa: string;
        fmt: string;
        funct3: string;
        opcode: string;
    };
    'fmadd.s': {
        isa: string;
        fmt: string;
        fp_fmt: string;
        opcode: string;
    };
    'fmsub.s': {
        isa: string;
        fmt: string;
        fp_fmt: string;
        opcode: string;
    };
    'fnmadd.s': {
        isa: string;
        fmt: string;
        fp_fmt: string;
        opcode: string;
    };
    'fnmsub.s': {
        isa: string;
        fmt: string;
        fp_fmt: string;
        opcode: string;
    };
    'fadd.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        opcode: string;
    };
    'fsub.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        opcode: string;
    };
    'fmul.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        opcode: string;
    };
    'fdiv.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        opcode: string;
    };
    'fsqrt.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fsgnj.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fsgnjn.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fsgnjx.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fmin.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fmax.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'feq.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'flt.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fle.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fcvt.w.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.wu.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.s.w': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.s.wu': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fclass.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        funct3: string;
        opcode: string;
    };
    'fmv.x.w': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        funct3: string;
        opcode: string;
    };
    'fmv.w.x': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        funct3: string;
        opcode: string;
    };
    'fcvt.l.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.lu.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.s.l': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.s.lu': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.t.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.tu.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.s.t': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.s.tu': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
};
export const ISA_D: {
    fld: {
        isa: string;
        fmt: string;
        funct3: string;
        opcode: string;
    };
    fsd: {
        isa: string;
        fmt: string;
        funct3: string;
        opcode: string;
    };
    'fmadd.d': {
        isa: string;
        fmt: string;
        fp_fmt: string;
        opcode: string;
    };
    'fmsub.d': {
        isa: string;
        fmt: string;
        fp_fmt: string;
        opcode: string;
    };
    'fnmadd.d': {
        isa: string;
        fmt: string;
        fp_fmt: string;
        opcode: string;
    };
    'fnmsub.d': {
        isa: string;
        fmt: string;
        fp_fmt: string;
        opcode: string;
    };
    'fadd.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        opcode: string;
    };
    'fsub.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        opcode: string;
    };
    'fmul.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        opcode: string;
    };
    'fdiv.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        opcode: string;
    };
    'fsqrt.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fsgnj.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fsgnjn.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fsgnjx.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fmin.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fmax.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'feq.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'flt.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fle.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fcvt.w.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.wu.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.d.w': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.d.wu': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.s.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.d.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fclass.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        funct3: string;
        opcode: string;
    };
    'fmv.x.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        funct3: string;
        opcode: string;
    };
    'fmv.d.x': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        funct3: string;
        opcode: string;
    };
    'fcvt.l.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.lu.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.d.l': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.d.lu': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.t.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.tu.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.d.t': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.d.tu': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
};
export const ISA_Q: {
    flq: {
        isa: string;
        fmt: string;
        funct3: string;
        opcode: string;
    };
    fsq: {
        isa: string;
        fmt: string;
        funct3: string;
        opcode: string;
    };
    'fmadd.q': {
        isa: string;
        fmt: string;
        fp_fmt: string;
        opcode: string;
    };
    'fmsub.q': {
        isa: string;
        fmt: string;
        fp_fmt: string;
        opcode: string;
    };
    'fnmadd.q': {
        isa: string;
        fmt: string;
        fp_fmt: string;
        opcode: string;
    };
    'fnmsub.q': {
        isa: string;
        fmt: string;
        fp_fmt: string;
        opcode: string;
    };
    'fadd.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        opcode: string;
    };
    'fsub.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        opcode: string;
    };
    'fmul.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        opcode: string;
    };
    'fdiv.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        opcode: string;
    };
    'fsqrt.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fsgnj.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fsgnjn.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fsgnjx.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fmin.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fmax.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'feq.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'flt.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fle.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        funct3: string;
        opcode: string;
    };
    'fcvt.w.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.wu.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.q.w': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.q.wu': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.s.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.q.s': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.d.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.q.d': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fclass.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        funct3: string;
        opcode: string;
    };
    'fcvt.l.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.lu.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.q.l': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.q.lu': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fmv.x.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        funct3: string;
        opcode: string;
    };
    'fmv.q.x': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        funct3: string;
        opcode: string;
    };
    'fcvt.t.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.tu.q': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.q.t': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
    'fcvt.q.tu': {
        isa: string;
        fmt: string;
        funct5: string;
        fp_fmt: string;
        rs2: string;
        opcode: string;
    };
};
export const ISA_C: {
    'c.lwsp': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        rdRs1Mask: number;
        rdRs1Excl: number[];
        uimm: boolean;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.ldsp': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        rdRs1Mask: number;
        rdRs1Excl: number[];
        uimm: boolean;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.lqsp': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        rdRs1Mask: number;
        rdRs1Excl: number[];
        uimm: boolean;
        immBits: (number | number[])[][];
        opcode: string;
    };
    'c.flwsp': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        rdRs1Mask: number;
        uimm: boolean;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.fldsp': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        rdRs1Mask: number;
        uimm: boolean;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.swsp': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: number[][];
        opcode: string;
    };
    'c.sdsp': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: number[][];
        opcode: string;
    };
    'c.sqsp': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: number[][];
        opcode: string;
    };
    'c.fswsp': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: number[][];
        opcode: string;
    };
    'c.fsdsp': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: number[][];
        opcode: string;
    };
    'c.lw': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.ld': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: number[][][];
        opcode: string;
    };
    'c.lq': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: (number | number[])[][];
        opcode: string;
    };
    'c.flw': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.fld': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: number[][][];
        opcode: string;
    };
    'c.sw': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.sd': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: number[][][];
        opcode: string;
    };
    'c.sq': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: (number | number[])[][];
        opcode: string;
    };
    'c.fsw': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.fsd': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        immBits: number[][][];
        opcode: string;
    };
    'c.j': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        immBits: (number | number[])[];
        opcode: string;
    };
    'c.jal': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        immBits: (number | number[])[];
        opcode: string;
    };
    'c.jr': {
        isa: string;
        xlens: number;
        fmt: string;
        funct4: string;
        rdRs1Mask: number;
        rdRs1Excl: number[];
        rs2Val: number;
        opcode: string;
    };
    'c.jalr': {
        isa: string;
        xlens: number;
        fmt: string;
        funct4: string;
        rdRs1Mask: number;
        rdRs1Excl: number[];
        rs2Val: number;
        opcode: string;
    };
    'c.beqz': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        immBits: (number | number[])[][];
        opcode: string;
    };
    'c.bnez': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        immBits: (number | number[])[][];
        opcode: string;
    };
    'c.li': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        rdRs1Mask: number;
        rdRs1Excl: number[];
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.lui': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        rdRs1Mask: number;
        rdRs1Excl: number[];
        nzimm: boolean;
        immBits: (number[] | number[][])[];
        immBitsLabels: (number[] | number[][])[];
        opcode: string;
    };
    'c.addi': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        rdRs1Mask: number;
        rdRs1Excl: number[];
        nzimm: boolean;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.addiw': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        rdRs1Mask: number;
        rdRs1Excl: number[];
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.addi16sp': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        rdRs1Mask: number;
        rdRs1Val: number;
        nzimm: boolean;
        immBits: (number | number[])[][];
        opcode: string;
    };
    'c.slli': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        rdRs1Mask: number;
        rdRs1Excl: number[];
        nzimm: boolean;
        uimm: boolean;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.slli64': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        rdRs1Mask: number;
        rdRs1Excl: number[];
        immVal: number;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.addi4spn': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        uimm: boolean;
        nzimm: boolean;
        immBits: (number | number[])[];
        opcode: string;
    };
    'c.srli': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        funct2: string;
        nzimm: boolean;
        uimm: boolean;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.srli64': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        funct2: string;
        immVal: number;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.srai': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        funct2: string;
        nzimm: boolean;
        uimm: boolean;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.srai64': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        funct2: string;
        immVal: number;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.andi': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        funct2: string;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.mv': {
        isa: string;
        xlens: number;
        fmt: string;
        funct4: string;
        rdRs1Mask: number;
        rdRs1Excl: number[];
        rs2Excl: number[];
        opcode: string;
    };
    'c.add': {
        isa: string;
        xlens: number;
        fmt: string;
        funct4: string;
        rdRs1Mask: number;
        rdRs1Excl: number[];
        rs2Excl: number[];
        opcode: string;
    };
    'c.and': {
        isa: string;
        xlens: number;
        fmt: string;
        funct6: string;
        funct2: string;
        opcode: string;
    };
    'c.or': {
        isa: string;
        xlens: number;
        fmt: string;
        funct6: string;
        funct2: string;
        opcode: string;
    };
    'c.xor': {
        isa: string;
        xlens: number;
        fmt: string;
        funct6: string;
        funct2: string;
        opcode: string;
    };
    'c.sub': {
        isa: string;
        xlens: number;
        fmt: string;
        funct6: string;
        funct2: string;
        opcode: string;
    };
    'c.subw': {
        isa: string;
        xlens: number;
        fmt: string;
        funct6: string;
        funct2: string;
        opcode: string;
    };
    'c.addw': {
        isa: string;
        xlens: number;
        fmt: string;
        funct6: string;
        funct2: string;
        opcode: string;
    };
    'c.nop': {
        isa: string;
        xlens: number;
        fmt: string;
        funct3: string;
        rdRs1Mask: number;
        rdRs1Val: number;
        immVal: number;
        immBits: (number[] | number[][])[];
        opcode: string;
    };
    'c.ebreak': {
        isa: string;
        xlens: number;
        fmt: string;
        funct4: string;
        rdRs1Mask: number;
        rdRs1Val: number;
        rs2Val: number;
        opcode: string;
    };
};
export const ISA_OP: {
    [x: string]: string;
};
export const ISA_OP_32: {
    [x: string]: string;
};
export const ISA_OP_64: {
    [x: string]: string;
};
export const ISA_LOAD: {
    [x: string]: string;
};
export const ISA_STORE: {
    [x: string]: string;
};
export const ISA_OP_IMM: {
    [x: string]: string | {
        [x: string]: string;
    };
};
export const ISA_OP_IMM_32: {
    [x: string]: string | {
        [x: string]: string;
    };
};
export const ISA_OP_IMM_64: {
    [x: string]: string | {
        [x: string]: string;
    };
};
export const ISA_BRANCH: {
    [x: string]: string;
};
export const ISA_MISC_MEM: {
    [x: string]: string;
};
export const ISA_SYSTEM: {
    [x: string]: string | {
        [x: string]: string;
    };
};
export const ISA_AMO: {
    [x: string]: string;
};
export const ISA_LOAD_FP: {
    [x: string]: string;
};
export const ISA_STORE_FP: {
    [x: string]: string;
};
export const ISA_MADD: {
    [x: string]: string;
};
export const ISA_MSUB: {
    [x: string]: string;
};
export const ISA_NMADD: {
    [x: string]: string;
};
export const ISA_NMSUB: {
    [x: string]: string;
};
export const ISA_OP_FP: {
    [x: string]: {
        [x: string]: string;
    } | {
        [x: string]: {
            [x: string]: string;
        };
    };
};
export const ISA_C0: {
    [x: string]: {};
};
export const ISA_C1: {
    [x: string]: {};
};
export const ISA_C2: {
    [x: string]: {};
};
export namespace REGISTER {
    const zero: string;
    const ra: string;
    const sp: string;
    const gp: string;
    const tp: string;
    const t0: string;
    const t1: string;
    const t2: string;
    const s0: string;
    const s1: string;
    const a0: string;
    const a1: string;
    const a2: string;
    const a3: string;
    const a4: string;
    const a5: string;
    const a6: string;
    const a7: string;
    const s2: string;
    const s3: string;
    const s4: string;
    const s5: string;
    const s6: string;
    const s7: string;
    const s8: string;
    const s9: string;
    const s10: string;
    const s11: string;
    const t3: string;
    const t4: string;
    const t5: string;
    const t6: string;
    const fp: string;
}
export namespace FLOAT_REGISTER {
    const ft0: string;
    const ft1: string;
    const ft2: string;
    const ft3: string;
    const ft4: string;
    const ft5: string;
    const ft6: string;
    const ft7: string;
    const fs0: string;
    const fs1: string;
    const fa0: string;
    const fa1: string;
    const fa2: string;
    const fa3: string;
    const fa4: string;
    const fa5: string;
    const fa6: string;
    const fa7: string;
    const fs2: string;
    const fs3: string;
    const fs4: string;
    const fs5: string;
    const fs6: string;
    const fs7: string;
    const fs8: string;
    const fs9: string;
    const fs10: string;
    const fs11: string;
    const ft8: string;
    const ft9: string;
    const ft10: string;
    const ft11: string;
}
export namespace CSR {
    const cycle: number;
    const cycleh: number;
    const dcsr: number;
    const dpc: number;
    const dscratch0: number;
    const dscratch1: number;
    const fcsr: number;
    const fflags: number;
    const frm: number;
    const hcounteren: number;
    const hedeleg: number;
    const hgatp: number;
    const hgeie: number;
    const hgeip: number;
    const hideleg: number;
    const hie: number;
    const hip: number;
    const hpmcounter3: number;
    const hpmcounter4: number;
    const hpmcounter5: number;
    const hpmcounter6: number;
    const hpmcounter7: number;
    const hpmcounter8: number;
    const hpmcounter9: number;
    const hpmcounter10: number;
    const hpmcounter11: number;
    const hpmcounter12: number;
    const hpmcounter13: number;
    const hpmcounter14: number;
    const hpmcounter15: number;
    const hpmcounter16: number;
    const hpmcounter17: number;
    const hpmcounter18: number;
    const hpmcounter19: number;
    const hpmcounter20: number;
    const hpmcounter21: number;
    const hpmcounter22: number;
    const hpmcounter23: number;
    const hpmcounter24: number;
    const hpmcounter25: number;
    const hpmcounter26: number;
    const hpmcounter27: number;
    const hpmcounter28: number;
    const hpmcounter29: number;
    const hpmcounter30: number;
    const hpmcounter31: number;
    const hpmcounter3h: number;
    const hpmcounter4h: number;
    const hpmcounter5h: number;
    const hpmcounter6h: number;
    const hpmcounter7h: number;
    const hpmcounter8h: number;
    const hpmcounter9h: number;
    const hpmcounter10h: number;
    const hpmcounter11h: number;
    const hpmcounter12h: number;
    const hpmcounter13h: number;
    const hpmcounter14h: number;
    const hpmcounter15h: number;
    const hpmcounter16h: number;
    const hpmcounter17h: number;
    const hpmcounter18h: number;
    const hpmcounter19h: number;
    const hpmcounter20h: number;
    const hpmcounter21h: number;
    const hpmcounter22h: number;
    const hpmcounter23h: number;
    const hpmcounter24h: number;
    const hpmcounter25h: number;
    const hpmcounter26h: number;
    const hpmcounter27h: number;
    const hpmcounter28h: number;
    const hpmcounter29h: number;
    const hpmcounter30h: number;
    const hpmcounter31h: number;
    const hstatus: number;
    const htimedelta: number;
    const htimedeltah: number;
    const htinst: number;
    const htval: number;
    const instret: number;
    const instreth: number;
    const marchid: number;
    const mbase: number;
    const mbound: number;
    const mcause: number;
    const mcounteren: number;
    const mcountinhibit: number;
    const mcycle: number;
    const mcycleh: number;
    const mdbase: number;
    const mdbound: number;
    const medeleg: number;
    const mepc: number;
    const mhartid: number;
    const mhpmcounter3: number;
    const mhpmcounter4: number;
    const mhpmcounter5: number;
    const mhpmcounter6: number;
    const mhpmcounter7: number;
    const mhpmcounter8: number;
    const mhpmcounter9: number;
    const mhpmcounter10: number;
    const mhpmcounter11: number;
    const mhpmcounter12: number;
    const mhpmcounter13: number;
    const mhpmcounter14: number;
    const mhpmcounter15: number;
    const mhpmcounter16: number;
    const mhpmcounter17: number;
    const mhpmcounter18: number;
    const mhpmcounter19: number;
    const mhpmcounter20: number;
    const mhpmcounter21: number;
    const mhpmcounter22: number;
    const mhpmcounter23: number;
    const mhpmcounter24: number;
    const mhpmcounter25: number;
    const mhpmcounter26: number;
    const mhpmcounter27: number;
    const mhpmcounter28: number;
    const mhpmcounter29: number;
    const mhpmcounter30: number;
    const mhpmcounter31: number;
    const mhpmcounter3h: number;
    const mhpmcounter4h: number;
    const mhpmcounter5h: number;
    const mhpmcounter6h: number;
    const mhpmcounter7h: number;
    const mhpmcounter8h: number;
    const mhpmcounter9h: number;
    const mhpmcounter10h: number;
    const mhpmcounter11h: number;
    const mhpmcounter12h: number;
    const mhpmcounter13h: number;
    const mhpmcounter14h: number;
    const mhpmcounter15h: number;
    const mhpmcounter16h: number;
    const mhpmcounter17h: number;
    const mhpmcounter18h: number;
    const mhpmcounter19h: number;
    const mhpmcounter20h: number;
    const mhpmcounter21h: number;
    const mhpmcounter22h: number;
    const mhpmcounter23h: number;
    const mhpmcounter24h: number;
    const mhpmcounter25h: number;
    const mhpmcounter26h: number;
    const mhpmcounter27h: number;
    const mhpmcounter28h: number;
    const mhpmcounter29h: number;
    const mhpmcounter30h: number;
    const mhpmcounter31h: number;
    const mhpmevent3: number;
    const mhpmevent4: number;
    const mhpmevent5: number;
    const mhpmevent6: number;
    const mhpmevent7: number;
    const mhpmevent8: number;
    const mhpmevent9: number;
    const mhpmevent10: number;
    const mhpmevent11: number;
    const mhpmevent12: number;
    const mhpmevent13: number;
    const mhpmevent14: number;
    const mhpmevent15: number;
    const mhpmevent16: number;
    const mhpmevent17: number;
    const mhpmevent18: number;
    const mhpmevent19: number;
    const mhpmevent20: number;
    const mhpmevent21: number;
    const mhpmevent22: number;
    const mhpmevent23: number;
    const mhpmevent24: number;
    const mhpmevent25: number;
    const mhpmevent26: number;
    const mhpmevent27: number;
    const mhpmevent28: number;
    const mhpmevent29: number;
    const mhpmevent30: number;
    const mhpmevent31: number;
    const mibase: number;
    const mibound: number;
    const mideleg: number;
    const mie: number;
    const mimpid: number;
    const minstret: number;
    const minstreth: number;
    const mip: number;
    const misa: number;
    const mscratch: number;
    const mstatus: number;
    const mstatush: number;
    const mtinst: number;
    const mtval: number;
    const mtval2: number;
    const mtvec: number;
    const mvendorid: number;
    const pmpaddr0: number;
    const pmpaddr1: number;
    const pmpaddr2: number;
    const pmpaddr3: number;
    const pmpaddr4: number;
    const pmpaddr5: number;
    const pmpaddr6: number;
    const pmpaddr7: number;
    const pmpaddr8: number;
    const pmpaddr9: number;
    const pmpaddr10: number;
    const pmpaddr11: number;
    const pmpaddr12: number;
    const pmpaddr13: number;
    const pmpaddr14: number;
    const pmpaddr15: number;
    const pmpaddr16: number;
    const pmpaddr17: number;
    const pmpaddr18: number;
    const pmpaddr19: number;
    const pmpaddr20: number;
    const pmpaddr21: number;
    const pmpaddr22: number;
    const pmpaddr23: number;
    const pmpaddr24: number;
    const pmpaddr25: number;
    const pmpaddr26: number;
    const pmpaddr27: number;
    const pmpaddr28: number;
    const pmpaddr29: number;
    const pmpaddr30: number;
    const pmpaddr31: number;
    const pmpaddr32: number;
    const pmpaddr33: number;
    const pmpaddr34: number;
    const pmpaddr35: number;
    const pmpaddr36: number;
    const pmpaddr37: number;
    const pmpaddr38: number;
    const pmpaddr39: number;
    const pmpaddr40: number;
    const pmpaddr41: number;
    const pmpaddr42: number;
    const pmpaddr43: number;
    const pmpaddr44: number;
    const pmpaddr45: number;
    const pmpaddr46: number;
    const pmpaddr47: number;
    const pmpaddr48: number;
    const pmpaddr49: number;
    const pmpaddr50: number;
    const pmpaddr51: number;
    const pmpaddr52: number;
    const pmpaddr53: number;
    const pmpaddr54: number;
    const pmpaddr55: number;
    const pmpaddr56: number;
    const pmpaddr57: number;
    const pmpaddr58: number;
    const pmpaddr59: number;
    const pmpaddr60: number;
    const pmpaddr61: number;
    const pmpaddr62: number;
    const pmpaddr63: number;
    const pmpcfg0: number;
    const pmpcfg1: number;
    const pmpcfg2: number;
    const pmpcfg3: number;
    const pmpcfg4: number;
    const pmpcfg5: number;
    const pmpcfg6: number;
    const pmpcfg7: number;
    const pmpcfg8: number;
    const pmpcfg9: number;
    const pmpcfg10: number;
    const pmpcfg11: number;
    const pmpcfg12: number;
    const pmpcfg13: number;
    const pmpcfg14: number;
    const pmpcfg15: number;
    const satp: number;
    const scause: number;
    const scounteren: number;
    const sedeleg: number;
    const sepc: number;
    const sideleg: number;
    const sie: number;
    const sip: number;
    const sscratch: number;
    const sstatus: number;
    const stval: number;
    const stvec: number;
    const tdata1: number;
    const tdata2: number;
    const tdata3: number;
    const time: number;
    const timeh: number;
    const tselect: number;
    const ucause: number;
    const uepc: number;
    const uie: number;
    const uip: number;
    const uscratch: number;
    const ustatus: number;
    const utval: number;
    const utvec: number;
    const vsatp: number;
    const vscause: number;
    const vsepc: number;
    const vsie: number;
    const vsip: number;
    const vsscratch: number;
    const vsstatus: number;
    const vstval: number;
    const vstvec: number;
}
export namespace FRAG {
    const UNSD: number;
    const CSR: number;
    const IMM: number;
    const OPC: number;
    const PRED: number;
    const RD: number;
    const RS1: number;
    const RS2: number;
    const RS3: number;
    const SUCC: number;
}
export const ISA: any;

✄
export const BASE={bin:2,dec:10,hex:16};export const XLEN={rv32:32,rv64:64,rv128:128};export const XLEN_MASK={rv32:1,rv64:2,rv128:4,all:7};export const FP_WIDTH={S:"010",D:"011",Q:"100"};export const FP_FMT={S:"00",D:"01",Q:"11"};export const FIELDS={opcode:{pos:[6,7],name:"opcode"},rd:{pos:[11,5],name:"rd"},funct3:{pos:[14,3],name:"funct3"},rs1:{pos:[19,5],name:"rs1"},rs2:{pos:[24,5],name:"rs2"},r_funct5:{pos:[31,5],name:"funct5"},r_funct7:{pos:[31,7],name:"funct7"},r_aq:{pos:[26,1],name:"aq"},r_rl:{pos:[25,1],name:"rl"},r_fp_fmt:{pos:[26,2],name:"fmt"},i_imm_11_0:{pos:[31,12],name:"imm[11:0]"},i_shtyp_11_7:{pos:[31,5],name:"shtyp[11:7]"},i_shtyp_11_6:{pos:[31,6],name:"shtyp[11:6]"},i_shtyp_11_5:{pos:[31,7],name:"shtyp[11:5]"},i_shtyp:{pos:[30,1],name:"shtyp"},i_shamt_6:{pos:[26,1],name:"shamt[6]"},i_shamt_6_0:{pos:[26,7],name:"shamt[6:0]"},i_shamt_5:{pos:[25,1],name:"shamt[5]"},i_shamt_5_0:{pos:[25,6],name:"shamt[5:0]"},i_shamt:{pos:[24,5],name:"shamt[4:0]"},i_funct12:{pos:[31,12],name:"funct12"},i_csr:{pos:[31,12],name:"csr"},i_imm_4_0:{pos:[19,5],name:"imm[4:0]"},i_fm:{pos:[31,4],name:"fm"},i_pred:{pos:[27,4],name:"pred"},i_succ:{pos:[23,4],name:"succ"},s_imm_4_0:{pos:[11,5],name:"imm[4:0]"},s_imm_11_5:{pos:[31,7],name:"imm[11:5]"},b_imm_4_1:{pos:[11,4],name:"imm[4:1]"},b_imm_11:{pos:[7,1],name:"imm[11]"},b_imm_10_5:{pos:[30,6],name:"imm[10:5]"},b_imm_12:{pos:[31,1],name:"imm[12]"},u_imm_31_12:{pos:[31,20],name:"imm[31:12]"},j_imm_20:{pos:[31,1],name:"imm[20]"},j_imm_10_1:{pos:[30,10],name:"imm[10:1]"},j_imm_11:{pos:[20,1],name:"imm[11]"},j_imm_19_12:{pos:[19,8],name:"imm[19:12]"},c_opcode:{pos:[1,2],name:"opcode"},c_funct6:{pos:[15,6],name:"funct6"},c_funct4:{pos:[15,4],name:"funct4"},c_funct3:{pos:[15,3],name:"funct3"},c_funct2:{pos:[6,2],name:"funct2"},c_funct2_cb:{pos:[11,2],name:"funct2"},c_rd:{pos:[11,5],name:"rd"},c_rs1:{pos:[11,5],name:"rs1"},c_rd_rs1:{pos:[11,5],name:"rd/rs1"},c_rs2:{pos:[6,5],name:"rs2"},c_rd_prime:{pos:[4,3],name:"rd'"},c_rs2_prime:{pos:[4,3],name:"rs2'"},c_rs1_prime:{pos:[9,3],name:"rs1'"},c_rd_rs1_prime:{pos:[9,3],name:"rd'/rs1'"},c_imm_ci_0:{pos:[12,1],name:"imm"},c_imm_ci_1:{pos:[6,5],name:"imm"},c_imm_css:{pos:[12,6],name:"imm"},c_imm_ciw:{pos:[12,8],name:"imm"},c_imm_cl_0:{pos:[12,3],name:"imm"},c_imm_cl_1:{pos:[6,2],name:"imm"},c_imm_cs_0:{pos:[12,3],name:"imm"},c_imm_cs_1:{pos:[6,2],name:"imm"},c_imm_cb_0:{pos:[12,3],name:"imm"},c_imm_cb_1:{pos:[6,5],name:"imm"},c_imm_cj:{pos:[12,11],name:"imm"},c_shamt_0:{pos:[12,1],name:"shamt"},c_shamt_1:{pos:[6,5],name:"shamt"}};export const OPCODE={LOAD:"0000011",LOAD_FP:"0000111",MISC_MEM:"0001111",OP_IMM:"0010011",AUIPC:"0010111",OP_IMM_32:"0011011",STORE:"0100011",STORE_FP:"0100111",AMO:"0101111",OP:"0110011",OP_32:"0111011",LUI:"0110111",MADD:"1000011",MSUB:"1000111",NMSUB:"1001011",NMADD:"1001111",OP_FP:"1010011",OP_IMM_64:"1011011",BRANCH:"1100011",JALR:"1100111",JAL:"1101111",SYSTEM:"1110011",OP_64:"1111011"};export const C_OPCODE={C0:"00",C1:"01",C2:"10"};export const ISA_RV32I={lui:{isa:"RV32I",fmt:"U-type",opcode:OPCODE.LUI},auipc:{isa:"RV32I",fmt:"U-type",opcode:OPCODE.AUIPC},jal:{isa:"RV32I",fmt:"J-type",opcode:OPCODE.JAL},jalr:{isa:"RV32I",fmt:"I-type",funct3:"000",opcode:OPCODE.JALR},beq:{isa:"RV32I",fmt:"B-type",funct3:"000",opcode:OPCODE.BRANCH},bne:{isa:"RV32I",fmt:"B-type",funct3:"001",opcode:OPCODE.BRANCH},blt:{isa:"RV32I",fmt:"B-type",funct3:"100",opcode:OPCODE.BRANCH},bge:{isa:"RV32I",fmt:"B-type",funct3:"101",opcode:OPCODE.BRANCH},bltu:{isa:"RV32I",fmt:"B-type",funct3:"110",opcode:OPCODE.BRANCH},bgeu:{isa:"RV32I",fmt:"B-type",funct3:"111",opcode:OPCODE.BRANCH},lb:{isa:"RV32I",fmt:"I-type",funct3:"000",opcode:OPCODE.LOAD},lh:{isa:"RV32I",fmt:"I-type",funct3:"001",opcode:OPCODE.LOAD},lw:{isa:"RV32I",fmt:"I-type",funct3:"010",opcode:OPCODE.LOAD},lbu:{isa:"RV32I",fmt:"I-type",funct3:"100",opcode:OPCODE.LOAD},lhu:{isa:"RV32I",fmt:"I-type",funct3:"101",opcode:OPCODE.LOAD},sb:{isa:"RV32I",fmt:"S-type",funct3:"000",opcode:OPCODE.STORE},sh:{isa:"RV32I",fmt:"S-type",funct3:"001",opcode:OPCODE.STORE},sw:{isa:"RV32I",fmt:"S-type",funct3:"010",opcode:OPCODE.STORE},addi:{isa:"RV32I",fmt:"I-type",funct3:"000",opcode:OPCODE.OP_IMM},slti:{isa:"RV32I",fmt:"I-type",funct3:"010",opcode:OPCODE.OP_IMM},sltiu:{isa:"RV32I",fmt:"I-type",funct3:"011",opcode:OPCODE.OP_IMM},xori:{isa:"RV32I",fmt:"I-type",funct3:"100",opcode:OPCODE.OP_IMM},ori:{isa:"RV32I",fmt:"I-type",funct3:"110",opcode:OPCODE.OP_IMM},andi:{isa:"RV32I",fmt:"I-type",funct3:"111",opcode:OPCODE.OP_IMM},slli:{isa:"RV32I",fmt:"I-type",shtyp:"0",funct3:"001",opcode:OPCODE.OP_IMM},srli:{isa:"RV32I",fmt:"I-type",shtyp:"0",funct3:"101",opcode:OPCODE.OP_IMM},srai:{isa:"RV32I",fmt:"I-type",shtyp:"1",funct3:"101",opcode:OPCODE.OP_IMM},add:{isa:"RV32I",fmt:"R-type",funct7:"0000000",funct3:"000",opcode:OPCODE.OP},sub:{isa:"RV32I",fmt:"R-type",funct7:"0100000",funct3:"000",opcode:OPCODE.OP},sll:{isa:"RV32I",fmt:"R-type",funct7:"0000000",funct3:"001",opcode:OPCODE.OP},slt:{isa:"RV32I",fmt:"R-type",funct7:"0000000",funct3:"010",opcode:OPCODE.OP},sltu:{isa:"RV32I",fmt:"R-type",funct7:"0000000",funct3:"011",opcode:OPCODE.OP},xor:{isa:"RV32I",fmt:"R-type",funct7:"0000000",funct3:"100",opcode:OPCODE.OP},srl:{isa:"RV32I",fmt:"R-type",funct7:"0000000",funct3:"101",opcode:OPCODE.OP},sra:{isa:"RV32I",fmt:"R-type",funct7:"0100000",funct3:"101",opcode:OPCODE.OP},or:{isa:"RV32I",fmt:"R-type",funct7:"0000000",funct3:"110",opcode:OPCODE.OP},and:{isa:"RV32I",fmt:"R-type",funct7:"0000000",funct3:"111",opcode:OPCODE.OP},fence:{isa:"RV32I",fmt:"I-type",funct3:"000",opcode:OPCODE.MISC_MEM},ecall:{isa:"RV32I",fmt:"I-type",funct12:"000000000000",funct3:"000",opcode:OPCODE.SYSTEM},ebreak:{isa:"RV32I",fmt:"I-type",funct12:"000000000001",funct3:"000",opcode:OPCODE.SYSTEM}};export const ISA_RV64I={addiw:{isa:"RV64I",fmt:"I-type",funct3:"000",opcode:OPCODE.OP_IMM_32},slliw:{isa:"RV64I",fmt:"I-type",shtyp:"0",funct3:"001",opcode:OPCODE.OP_IMM_32},srliw:{isa:"RV64I",fmt:"I-type",shtyp:"0",funct3:"101",opcode:OPCODE.OP_IMM_32},sraiw:{isa:"RV64I",fmt:"I-type",shtyp:"1",funct3:"101",opcode:OPCODE.OP_IMM_32},addw:{isa:"RV64I",fmt:"R-type",funct7:"0000000",funct3:"000",opcode:OPCODE.OP_32},subw:{isa:"RV64I",fmt:"R-type",funct7:"0100000",funct3:"000",opcode:OPCODE.OP_32},sllw:{isa:"RV64I",fmt:"R-type",funct7:"0000000",funct3:"001",opcode:OPCODE.OP_32},srlw:{isa:"RV64I",fmt:"R-type",funct7:"0000000",funct3:"101",opcode:OPCODE.OP_32},sraw:{isa:"RV64I",fmt:"R-type",funct7:"0100000",funct3:"101",opcode:OPCODE.OP_32},ld:{isa:"RV64I",fmt:"I-type",funct3:"011",opcode:OPCODE.LOAD},lwu:{isa:"RV64I",fmt:"I-type",funct3:"110",opcode:OPCODE.LOAD},sd:{isa:"RV64I",fmt:"S-type",funct3:"011",opcode:OPCODE.STORE}};export const ISA_RV128I={addid:{isa:"RV128I",fmt:"I-type",funct3:"000",opcode:OPCODE.OP_IMM_64},sllid:{isa:"RV128I",fmt:"I-type",shtyp:"0",funct3:"001",opcode:OPCODE.OP_IMM_64},srlid:{isa:"RV128I",fmt:"I-type",shtyp:"0",funct3:"101",opcode:OPCODE.OP_IMM_64},sraid:{isa:"RV128I",fmt:"I-type",shtyp:"1",funct3:"101",opcode:OPCODE.OP_IMM_64},addd:{isa:"RV128I",fmt:"R-type",funct7:"0000000",funct3:"000",opcode:OPCODE.OP_64},subd:{isa:"RV128I",fmt:"R-type",funct7:"0100000",funct3:"000",opcode:OPCODE.OP_64},slld:{isa:"RV128I",fmt:"R-type",funct7:"0000000",funct3:"001",opcode:OPCODE.OP_64},srld:{isa:"RV128I",fmt:"R-type",funct7:"0000000",funct3:"101",opcode:OPCODE.OP_64},srad:{isa:"RV128I",fmt:"R-type",funct7:"0100000",funct3:"101",opcode:OPCODE.OP_64},lq:{isa:"RV128I",fmt:"I-type",funct3:"010",opcode:OPCODE.MISC_MEM},ldu:{isa:"RV128I",fmt:"I-type",funct3:"111",opcode:OPCODE.LOAD},sq:{isa:"RV128I",fmt:"S-type",funct3:"100",opcode:OPCODE.STORE}};export const ISA_Zifencei={"fence.i":{isa:"Zifencei",fmt:"I-type",funct3:"001",opcode:OPCODE.MISC_MEM}};export const ISA_Zicsr={csrrw:{isa:"Zicsr",fmt:"I-type",funct3:"001",opcode:OPCODE.SYSTEM},csrrs:{isa:"Zicsr",fmt:"I-type",funct3:"010",opcode:OPCODE.SYSTEM},csrrc:{isa:"Zicsr",fmt:"I-type",funct3:"011",opcode:OPCODE.SYSTEM},csrrwi:{isa:"Zicsr",fmt:"I-type",funct3:"101",opcode:OPCODE.SYSTEM},csrrsi:{isa:"Zicsr",fmt:"I-type",funct3:"110",opcode:OPCODE.SYSTEM},csrrci:{isa:"Zicsr",fmt:"I-type",funct3:"111",opcode:OPCODE.SYSTEM}};export const ISA_M={mul:{isa:"RV32M",fmt:"R-type",funct7:"0000001",funct3:"000",opcode:OPCODE.OP},mulh:{isa:"RV32M",fmt:"R-type",funct7:"0000001",funct3:"001",opcode:OPCODE.OP},mulhsu:{isa:"RV32M",fmt:"R-type",funct7:"0000001",funct3:"010",opcode:OPCODE.OP},mulhu:{isa:"RV32M",fmt:"R-type",funct7:"0000001",funct3:"011",opcode:OPCODE.OP},div:{isa:"RV32M",fmt:"R-type",funct7:"0000001",funct3:"100",opcode:OPCODE.OP},divu:{isa:"RV32M",fmt:"R-type",funct7:"0000001",funct3:"101",opcode:OPCODE.OP},rem:{isa:"RV32M",fmt:"R-type",funct7:"0000001",funct3:"110",opcode:OPCODE.OP},remu:{isa:"RV32M",fmt:"R-type",funct7:"0000001",funct3:"111",opcode:OPCODE.OP},mulw:{isa:"RV64M",fmt:"R-type",funct7:"0000001",funct3:"000",opcode:OPCODE.OP_32},divw:{isa:"RV64M",fmt:"R-type",funct7:"0000001",funct3:"100",opcode:OPCODE.OP_32},divuw:{isa:"RV64M",fmt:"R-type",funct7:"0000001",funct3:"101",opcode:OPCODE.OP_32},remw:{isa:"RV64M",fmt:"R-type",funct7:"0000001",funct3:"110",opcode:OPCODE.OP_32},remuw:{isa:"RV64M",fmt:"R-type",funct7:"0000001",funct3:"111",opcode:OPCODE.OP_32},muld:{isa:"RV128M",fmt:"R-type",funct7:"0000001",funct3:"000",opcode:OPCODE.OP_64},divd:{isa:"RV128M",fmt:"R-type",funct7:"0000001",funct3:"100",opcode:OPCODE.OP_64},divud:{isa:"RV128M",fmt:"R-type",funct7:"0000001",funct3:"101",opcode:OPCODE.OP_64},remd:{isa:"RV128M",fmt:"R-type",funct7:"0000001",funct3:"110",opcode:OPCODE.OP_64},remud:{isa:"RV128M",fmt:"R-type",funct7:"0000001",funct3:"111",opcode:OPCODE.OP_64}};export const ISA_A={"lr.w":{isa:"RV32A",fmt:"R-type",funct5:"00010",funct3:"010",opcode:OPCODE.AMO},"sc.w":{isa:"RV32A",fmt:"R-type",funct5:"00011",funct3:"010",opcode:OPCODE.AMO},"amoswap.w":{isa:"RV32A",fmt:"R-type",funct5:"00001",funct3:"010",opcode:OPCODE.AMO},"amoadd.w":{isa:"RV32A",fmt:"R-type",funct5:"00000",funct3:"010",opcode:OPCODE.AMO},"amoxor.w":{isa:"RV32A",fmt:"R-type",funct5:"00100",funct3:"010",opcode:OPCODE.AMO},"amoand.w":{isa:"RV32A",fmt:"R-type",funct5:"01100",funct3:"010",opcode:OPCODE.AMO},"amoor.w":{isa:"RV32A",fmt:"R-type",funct5:"01000",funct3:"010",opcode:OPCODE.AMO},"amomin.w":{isa:"RV32A",fmt:"R-type",funct5:"10000",funct3:"010",opcode:OPCODE.AMO},"amomax.w":{isa:"RV32A",fmt:"R-type",funct5:"10100",funct3:"010",opcode:OPCODE.AMO},"amominu.w":{isa:"RV32A",fmt:"R-type",funct5:"11000",funct3:"010",opcode:OPCODE.AMO},"amomaxu.w":{isa:"RV32A",fmt:"R-type",funct5:"11100",funct3:"010",opcode:OPCODE.AMO},"lr.d":{isa:"RV64A",fmt:"R-type",funct5:"00010",funct3:"011",opcode:OPCODE.AMO},"sc.d":{isa:"RV64A",fmt:"R-type",funct5:"00011",funct3:"011",opcode:OPCODE.AMO},"amoswap.d":{isa:"RV64A",fmt:"R-type",funct5:"00001",funct3:"011",opcode:OPCODE.AMO},"amoadd.d":{isa:"RV64A",fmt:"R-type",funct5:"00000",funct3:"011",opcode:OPCODE.AMO},"amoxor.d":{isa:"RV64A",fmt:"R-type",funct5:"00100",funct3:"011",opcode:OPCODE.AMO},"amoand.d":{isa:"RV64A",fmt:"R-type",funct5:"01100",funct3:"011",opcode:OPCODE.AMO},"amoor.d":{isa:"RV64A",fmt:"R-type",funct5:"01000",funct3:"011",opcode:OPCODE.AMO},"amomin.d":{isa:"RV64A",fmt:"R-type",funct5:"10000",funct3:"011",opcode:OPCODE.AMO},"amomax.d":{isa:"RV64A",fmt:"R-type",funct5:"10100",funct3:"011",opcode:OPCODE.AMO},"amominu.d":{isa:"RV64A",fmt:"R-type",funct5:"11000",funct3:"011",opcode:OPCODE.AMO},"amomaxu.d":{isa:"RV64A",fmt:"R-type",funct5:"11100",funct3:"011",opcode:OPCODE.AMO},"lr.q":{isa:"RV128A",fmt:"R-type",funct5:"00010",funct3:"100",opcode:OPCODE.AMO},"sc.q":{isa:"RV128A",fmt:"R-type",funct5:"00011",funct3:"100",opcode:OPCODE.AMO},"amoswap.q":{isa:"RV128A",fmt:"R-type",funct5:"00001",funct3:"100",opcode:OPCODE.AMO},"amoadd.q":{isa:"RV128A",fmt:"R-type",funct5:"00000",funct3:"100",opcode:OPCODE.AMO},"amoxor.q":{isa:"RV128A",fmt:"R-type",funct5:"00100",funct3:"100",opcode:OPCODE.AMO},"amoand.q":{isa:"RV128A",fmt:"R-type",funct5:"01100",funct3:"100",opcode:OPCODE.AMO},"amoor.q":{isa:"RV128A",fmt:"R-type",funct5:"01000",funct3:"100",opcode:OPCODE.AMO},"amomin.q":{isa:"RV128A",fmt:"R-type",funct5:"10000",funct3:"100",opcode:OPCODE.AMO},"amomax.q":{isa:"RV128A",fmt:"R-type",funct5:"10100",funct3:"100",opcode:OPCODE.AMO},"amominu.q":{isa:"RV128A",fmt:"R-type",funct5:"11000",funct3:"100",opcode:OPCODE.AMO},"amomaxu.q":{isa:"RV128A",fmt:"R-type",funct5:"11100",funct3:"100",opcode:OPCODE.AMO}};export const ISA_F={flw:{isa:"RV32F",fmt:"I-type",funct3:FP_WIDTH.S,opcode:OPCODE.LOAD_FP},fsw:{isa:"RV32F",fmt:"S-type",funct3:FP_WIDTH.S,opcode:OPCODE.STORE_FP},"fmadd.s":{isa:"RV32F",fmt:"R4-type",fp_fmt:FP_FMT.S,opcode:OPCODE.MADD},"fmsub.s":{isa:"RV32F",fmt:"R4-type",fp_fmt:FP_FMT.S,opcode:OPCODE.MSUB},"fnmadd.s":{isa:"RV32F",fmt:"R4-type",fp_fmt:FP_FMT.S,opcode:OPCODE.NMADD},"fnmsub.s":{isa:"RV32F",fmt:"R4-type",fp_fmt:FP_FMT.S,opcode:OPCODE.NMSUB},"fadd.s":{isa:"RV32F",fmt:"R-type",funct5:"00000",fp_fmt:FP_FMT.S,opcode:OPCODE.OP_FP},"fsub.s":{isa:"RV32F",fmt:"R-type",funct5:"00001",fp_fmt:FP_FMT.S,opcode:OPCODE.OP_FP},"fmul.s":{isa:"RV32F",fmt:"R-type",funct5:"00010",fp_fmt:FP_FMT.S,opcode:OPCODE.OP_FP},"fdiv.s":{isa:"RV32F",fmt:"R-type",funct5:"00011",fp_fmt:FP_FMT.S,opcode:OPCODE.OP_FP},"fsqrt.s":{isa:"RV32F",fmt:"R-type",funct5:"01011",fp_fmt:FP_FMT.S,rs2:"00000",opcode:OPCODE.OP_FP},"fsgnj.s":{isa:"RV32F",fmt:"R-type",funct5:"00100",fp_fmt:FP_FMT.S,funct3:"000",opcode:OPCODE.OP_FP},"fsgnjn.s":{isa:"RV32F",fmt:"R-type",funct5:"00100",fp_fmt:FP_FMT.S,funct3:"001",opcode:OPCODE.OP_FP},"fsgnjx.s":{isa:"RV32F",fmt:"R-type",funct5:"00100",fp_fmt:FP_FMT.S,funct3:"010",opcode:OPCODE.OP_FP},"fmin.s":{isa:"RV32F",fmt:"R-type",funct5:"00101",fp_fmt:FP_FMT.S,funct3:"000",opcode:OPCODE.OP_FP},"fmax.s":{isa:"RV32F",fmt:"R-type",funct5:"00101",fp_fmt:FP_FMT.S,funct3:"001",opcode:OPCODE.OP_FP},"feq.s":{isa:"RV32F",fmt:"R-type",funct5:"10100",fp_fmt:FP_FMT.S,funct3:"010",opcode:OPCODE.OP_FP},"flt.s":{isa:"RV32F",fmt:"R-type",funct5:"10100",fp_fmt:FP_FMT.S,funct3:"001",opcode:OPCODE.OP_FP},"fle.s":{isa:"RV32F",fmt:"R-type",funct5:"10100",fp_fmt:FP_FMT.S,funct3:"000",opcode:OPCODE.OP_FP},"fcvt.w.s":{isa:"RV32F",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.S,rs2:"00000",opcode:OPCODE.OP_FP},"fcvt.wu.s":{isa:"RV32F",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.S,rs2:"00001",opcode:OPCODE.OP_FP},"fcvt.s.w":{isa:"RV32F",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.S,rs2:"00000",opcode:OPCODE.OP_FP},"fcvt.s.wu":{isa:"RV32F",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.S,rs2:"00001",opcode:OPCODE.OP_FP},"fclass.s":{isa:"RV32F",fmt:"R-type",funct5:"11100",fp_fmt:FP_FMT.S,rs2:"00000",funct3:"001",opcode:OPCODE.OP_FP},"fmv.x.w":{isa:"RV32F",fmt:"R-type",funct5:"11100",fp_fmt:FP_FMT.S,rs2:"00000",funct3:"000",opcode:OPCODE.OP_FP},"fmv.w.x":{isa:"RV32F",fmt:"R-type",funct5:"11110",fp_fmt:FP_FMT.S,rs2:"00000",funct3:"000",opcode:OPCODE.OP_FP},"fcvt.l.s":{isa:"RV64F",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.S,rs2:"00010",opcode:OPCODE.OP_FP},"fcvt.lu.s":{isa:"RV64F",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.S,rs2:"00011",opcode:OPCODE.OP_FP},"fcvt.s.l":{isa:"RV64F",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.S,rs2:"00010",opcode:OPCODE.OP_FP},"fcvt.s.lu":{isa:"RV64F",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.S,rs2:"00011",opcode:OPCODE.OP_FP},"fcvt.t.s":{isa:"RV128F",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.S,rs2:"00100",opcode:OPCODE.OP_FP},"fcvt.tu.s":{isa:"RV128F",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.S,rs2:"00101",opcode:OPCODE.OP_FP},"fcvt.s.t":{isa:"RV128F",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.S,rs2:"00100",opcode:OPCODE.OP_FP},"fcvt.s.tu":{isa:"RV128F",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.S,rs2:"00101",opcode:OPCODE.OP_FP}};export const ISA_D={fld:{isa:"RV32D",fmt:"I-type",funct3:FP_WIDTH.D,opcode:OPCODE.LOAD_FP},fsd:{isa:"RV32D",fmt:"S-type",funct3:FP_WIDTH.D,opcode:OPCODE.STORE_FP},"fmadd.d":{isa:"RV32D",fmt:"R4-type",fp_fmt:FP_FMT.D,opcode:OPCODE.MADD},"fmsub.d":{isa:"RV32D",fmt:"R4-type",fp_fmt:FP_FMT.D,opcode:OPCODE.MSUB},"fnmadd.d":{isa:"RV32D",fmt:"R4-type",fp_fmt:FP_FMT.D,opcode:OPCODE.NMADD},"fnmsub.d":{isa:"RV32D",fmt:"R4-type",fp_fmt:FP_FMT.D,opcode:OPCODE.NMSUB},"fadd.d":{isa:"RV32D",fmt:"R-type",funct5:"00000",fp_fmt:FP_FMT.D,opcode:OPCODE.OP_FP},"fsub.d":{isa:"RV32D",fmt:"R-type",funct5:"00001",fp_fmt:FP_FMT.D,opcode:OPCODE.OP_FP},"fmul.d":{isa:"RV32D",fmt:"R-type",funct5:"00010",fp_fmt:FP_FMT.D,opcode:OPCODE.OP_FP},"fdiv.d":{isa:"RV32D",fmt:"R-type",funct5:"00011",fp_fmt:FP_FMT.D,opcode:OPCODE.OP_FP},"fsqrt.d":{isa:"RV32D",fmt:"R-type",funct5:"01011",fp_fmt:FP_FMT.D,rs2:"00000",opcode:OPCODE.OP_FP},"fsgnj.d":{isa:"RV32D",fmt:"R-type",funct5:"00100",fp_fmt:FP_FMT.D,funct3:"000",opcode:OPCODE.OP_FP},"fsgnjn.d":{isa:"RV32D",fmt:"R-type",funct5:"00100",fp_fmt:FP_FMT.D,funct3:"001",opcode:OPCODE.OP_FP},"fsgnjx.d":{isa:"RV32D",fmt:"R-type",funct5:"00100",fp_fmt:FP_FMT.D,funct3:"010",opcode:OPCODE.OP_FP},"fmin.d":{isa:"RV32D",fmt:"R-type",funct5:"00101",fp_fmt:FP_FMT.D,funct3:"000",opcode:OPCODE.OP_FP},"fmax.d":{isa:"RV32D",fmt:"R-type",funct5:"00101",fp_fmt:FP_FMT.D,funct3:"001",opcode:OPCODE.OP_FP},"feq.d":{isa:"RV32D",fmt:"R-type",funct5:"10100",fp_fmt:FP_FMT.D,funct3:"010",opcode:OPCODE.OP_FP},"flt.d":{isa:"RV32D",fmt:"R-type",funct5:"10100",fp_fmt:FP_FMT.D,funct3:"001",opcode:OPCODE.OP_FP},"fle.d":{isa:"RV32D",fmt:"R-type",funct5:"10100",fp_fmt:FP_FMT.D,funct3:"000",opcode:OPCODE.OP_FP},"fcvt.w.d":{isa:"RV32D",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.D,rs2:"00000",opcode:OPCODE.OP_FP},"fcvt.wu.d":{isa:"RV32D",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.D,rs2:"00001",opcode:OPCODE.OP_FP},"fcvt.d.w":{isa:"RV32D",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.D,rs2:"00000",opcode:OPCODE.OP_FP},"fcvt.d.wu":{isa:"RV32D",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.D,rs2:"00001",opcode:OPCODE.OP_FP},"fcvt.s.d":{isa:"RV32D",fmt:"R-type",funct5:"01000",fp_fmt:FP_FMT.S,rs2:"000"+FP_FMT.D,opcode:OPCODE.OP_FP},"fcvt.d.s":{isa:"RV32D",fmt:"R-type",funct5:"01000",fp_fmt:FP_FMT.D,rs2:"000"+FP_FMT.S,opcode:OPCODE.OP_FP},"fclass.d":{isa:"RV32D",fmt:"R-type",funct5:"11100",fp_fmt:FP_FMT.D,rs2:"00000",funct3:"001",opcode:OPCODE.OP_FP},"fmv.x.d":{isa:"RV64D",fmt:"R-type",funct5:"11100",fp_fmt:FP_FMT.D,rs2:"00000",funct3:"000",opcode:OPCODE.OP_FP},"fmv.d.x":{isa:"RV64D",fmt:"R-type",funct5:"11110",fp_fmt:FP_FMT.D,rs2:"00000",funct3:"000",opcode:OPCODE.OP_FP},"fcvt.l.d":{isa:"RV64D",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.D,rs2:"00010",opcode:OPCODE.OP_FP},"fcvt.lu.d":{isa:"RV64D",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.D,rs2:"00011",opcode:OPCODE.OP_FP},"fcvt.d.l":{isa:"RV64D",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.D,rs2:"00010",opcode:OPCODE.OP_FP},"fcvt.d.lu":{isa:"RV64D",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.D,rs2:"00011",opcode:OPCODE.OP_FP},"fcvt.t.d":{isa:"RV128D",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.D,rs2:"00100",opcode:OPCODE.OP_FP},"fcvt.tu.d":{isa:"RV128D",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.D,rs2:"00101",opcode:OPCODE.OP_FP},"fcvt.d.t":{isa:"RV128D",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.D,rs2:"00100",opcode:OPCODE.OP_FP},"fcvt.d.tu":{isa:"RV128D",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.D,rs2:"00101",opcode:OPCODE.OP_FP}};export const ISA_Q={flq:{isa:"RV32Q",fmt:"I-type",funct3:FP_WIDTH.Q,opcode:OPCODE.LOAD_FP},fsq:{isa:"RV32Q",fmt:"S-type",funct3:FP_WIDTH.Q,opcode:OPCODE.STORE_FP},"fmadd.q":{isa:"RV32Q",fmt:"R4-type",fp_fmt:FP_FMT.Q,opcode:OPCODE.MADD},"fmsub.q":{isa:"RV32Q",fmt:"R4-type",fp_fmt:FP_FMT.Q,opcode:OPCODE.MSUB},"fnmadd.q":{isa:"RV32Q",fmt:"R4-type",fp_fmt:FP_FMT.Q,opcode:OPCODE.NMADD},"fnmsub.q":{isa:"RV32Q",fmt:"R4-type",fp_fmt:FP_FMT.Q,opcode:OPCODE.NMSUB},"fadd.q":{isa:"RV32Q",fmt:"R-type",funct5:"00000",fp_fmt:FP_FMT.Q,opcode:OPCODE.OP_FP},"fsub.q":{isa:"RV32Q",fmt:"R-type",funct5:"00001",fp_fmt:FP_FMT.Q,opcode:OPCODE.OP_FP},"fmul.q":{isa:"RV32Q",fmt:"R-type",funct5:"00010",fp_fmt:FP_FMT.Q,opcode:OPCODE.OP_FP},"fdiv.q":{isa:"RV32Q",fmt:"R-type",funct5:"00011",fp_fmt:FP_FMT.Q,opcode:OPCODE.OP_FP},"fsqrt.q":{isa:"RV32Q",fmt:"R-type",funct5:"01011",fp_fmt:FP_FMT.Q,rs2:"00000",opcode:OPCODE.OP_FP},"fsgnj.q":{isa:"RV32Q",fmt:"R-type",funct5:"00100",fp_fmt:FP_FMT.Q,funct3:"000",opcode:OPCODE.OP_FP},"fsgnjn.q":{isa:"RV32Q",fmt:"R-type",funct5:"00100",fp_fmt:FP_FMT.Q,funct3:"001",opcode:OPCODE.OP_FP},"fsgnjx.q":{isa:"RV32Q",fmt:"R-type",funct5:"00100",fp_fmt:FP_FMT.Q,funct3:"010",opcode:OPCODE.OP_FP},"fmin.q":{isa:"RV32Q",fmt:"R-type",funct5:"00101",fp_fmt:FP_FMT.Q,funct3:"000",opcode:OPCODE.OP_FP},"fmax.q":{isa:"RV32Q",fmt:"R-type",funct5:"00101",fp_fmt:FP_FMT.Q,funct3:"001",opcode:OPCODE.OP_FP},"feq.q":{isa:"RV32Q",fmt:"R-type",funct5:"10100",fp_fmt:FP_FMT.Q,funct3:"010",opcode:OPCODE.OP_FP},"flt.q":{isa:"RV32Q",fmt:"R-type",funct5:"10100",fp_fmt:FP_FMT.Q,funct3:"001",opcode:OPCODE.OP_FP},"fle.q":{isa:"RV32Q",fmt:"R-type",funct5:"10100",fp_fmt:FP_FMT.Q,funct3:"000",opcode:OPCODE.OP_FP},"fcvt.w.q":{isa:"RV32Q",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.Q,rs2:"00000",opcode:OPCODE.OP_FP},"fcvt.wu.q":{isa:"RV32Q",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.Q,rs2:"00001",opcode:OPCODE.OP_FP},"fcvt.q.w":{isa:"RV32Q",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.Q,rs2:"00000",opcode:OPCODE.OP_FP},"fcvt.q.wu":{isa:"RV32Q",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.Q,rs2:"00001",opcode:OPCODE.OP_FP},"fcvt.s.q":{isa:"RV32Q",fmt:"R-type",funct5:"01000",fp_fmt:FP_FMT.S,rs2:"000"+FP_FMT.Q,opcode:OPCODE.OP_FP},"fcvt.q.s":{isa:"RV32Q",fmt:"R-type",funct5:"01000",fp_fmt:FP_FMT.Q,rs2:"000"+FP_FMT.S,opcode:OPCODE.OP_FP},"fcvt.d.q":{isa:"RV32Q",fmt:"R-type",funct5:"01000",fp_fmt:FP_FMT.D,rs2:"000"+FP_FMT.Q,opcode:OPCODE.OP_FP},"fcvt.q.d":{isa:"RV32Q",fmt:"R-type",funct5:"01000",fp_fmt:FP_FMT.Q,rs2:"000"+FP_FMT.D,opcode:OPCODE.OP_FP},"fclass.q":{isa:"RV32Q",fmt:"R-type",funct5:"11100",fp_fmt:FP_FMT.Q,rs2:"00000",funct3:"001",opcode:OPCODE.OP_FP},"fcvt.l.q":{isa:"RV64Q",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.Q,rs2:"00010",opcode:OPCODE.OP_FP},"fcvt.lu.q":{isa:"RV64Q",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.Q,rs2:"00011",opcode:OPCODE.OP_FP},"fcvt.q.l":{isa:"RV64Q",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.Q,rs2:"00010",opcode:OPCODE.OP_FP},"fcvt.q.lu":{isa:"RV64Q",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.Q,rs2:"00011",opcode:OPCODE.OP_FP},"fmv.x.q":{isa:"RV128Q",fmt:"R-type",funct5:"11100",fp_fmt:FP_FMT.Q,rs2:"00000",funct3:"000",opcode:OPCODE.OP_FP},"fmv.q.x":{isa:"RV128Q",fmt:"R-type",funct5:"11110",fp_fmt:FP_FMT.Q,rs2:"00000",funct3:"000",opcode:OPCODE.OP_FP},"fcvt.t.q":{isa:"RV128Q",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.Q,rs2:"00100",opcode:OPCODE.OP_FP},"fcvt.tu.q":{isa:"RV128Q",fmt:"R-type",funct5:"11000",fp_fmt:FP_FMT.Q,rs2:"00101",opcode:OPCODE.OP_FP},"fcvt.q.t":{isa:"RV128Q",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.Q,rs2:"00100",opcode:OPCODE.OP_FP},"fcvt.q.tu":{isa:"RV128Q",fmt:"R-type",funct5:"11010",fp_fmt:FP_FMT.Q,rs2:"00101",opcode:OPCODE.OP_FP}};export const ISA_C={"c.lwsp":{isa:"C",xlens:7,fmt:"CI-type",funct3:"010",rdRs1Mask:2,rdRs1Excl:[0],uimm:!0,immBits:[[5],[[4,2],[7,6]]],opcode:C_OPCODE.C2},"c.ldsp":{isa:"C",xlens:6,fmt:"CI-type",funct3:"011",rdRs1Mask:2,rdRs1Excl:[0],uimm:!0,immBits:[[5],[[4,3],[8,6]]],opcode:C_OPCODE.C2},"c.lqsp":{isa:"C",xlens:4,fmt:"CI-type",funct3:"001",rdRs1Mask:2,rdRs1Excl:[0],uimm:!0,immBits:[[5],[4,[9,6]]],opcode:C_OPCODE.C2},"c.flwsp":{isa:"FC",xlens:1,fmt:"CI-type",funct3:"011",rdRs1Mask:2,uimm:!0,immBits:[[5],[[4,2],[7,6]]],opcode:C_OPCODE.C2},"c.fldsp":{isa:"DC",xlens:3,fmt:"CI-type",funct3:"001",rdRs1Mask:2,uimm:!0,immBits:[[5],[[4,3],[8,6]]],opcode:C_OPCODE.C2},"c.swsp":{isa:"C",xlens:7,fmt:"CSS-type",funct3:"110",uimm:!0,immBits:[[5,2],[7,6]],opcode:C_OPCODE.C2},"c.sdsp":{isa:"C",xlens:6,fmt:"CSS-type",funct3:"111",uimm:!0,immBits:[[5,3],[8,6]],opcode:C_OPCODE.C2},"c.sqsp":{isa:"C",xlens:4,fmt:"CSS-type",funct3:"101",uimm:!0,immBits:[[5,4],[9,6]],opcode:C_OPCODE.C2},"c.fswsp":{isa:"FC",xlens:1,fmt:"CSS-type",funct3:"111",uimm:!0,immBits:[[5,2],[7,6]],opcode:C_OPCODE.C2},"c.fsdsp":{isa:"DC",xlens:3,fmt:"CSS-type",funct3:"101",uimm:!0,immBits:[[5,3],[8,6]],opcode:C_OPCODE.C2},"c.lw":{isa:"C",xlens:7,fmt:"CL-type",funct3:"010",uimm:!0,immBits:[[[5,3]],[2,6]],opcode:C_OPCODE.C0},"c.ld":{isa:"C",xlens:6,fmt:"CL-type",funct3:"011",uimm:!0,immBits:[[[5,3]],[[7,6]]],opcode:C_OPCODE.C0},"c.lq":{isa:"C",xlens:4,fmt:"CL-type",funct3:"001",uimm:!0,immBits:[[[5,4],8],[[7,6]]],opcode:C_OPCODE.C0},"c.flw":{isa:"FC",xlens:1,fmt:"CL-type",funct3:"011",uimm:!0,immBits:[[[5,3]],[2,6]],opcode:C_OPCODE.C0},"c.fld":{isa:"DC",xlens:3,fmt:"CL-type",funct3:"001",uimm:!0,immBits:[[[5,3]],[[7,6]]],opcode:C_OPCODE.C0},"c.sw":{isa:"C",xlens:7,fmt:"CS-type",funct3:"110",uimm:!0,immBits:[[[5,3]],[2,6]],opcode:C_OPCODE.C0},"c.sd":{isa:"C",xlens:6,fmt:"CS-type",funct3:"111",uimm:!0,immBits:[[[5,3]],[[7,6]]],opcode:C_OPCODE.C0},"c.sq":{isa:"C",xlens:4,fmt:"CS-type",funct3:"101",uimm:!0,immBits:[[[5,4],8],[[7,6]]],opcode:C_OPCODE.C0},"c.fsw":{isa:"FC",xlens:1,fmt:"CS-type",funct3:"111",uimm:!0,immBits:[[[5,3]],[2,6]],opcode:C_OPCODE.C0},"c.fsd":{isa:"DC",xlens:3,fmt:"CS-type",funct3:"101",uimm:!0,immBits:[[[5,3]],[[7,6]]],opcode:C_OPCODE.C0},"c.j":{isa:"C",xlens:5,fmt:"CJ-type",funct3:"101",immBits:[11,4,[9,8],10,6,7,[3,1],5],opcode:C_OPCODE.C1},"c.jal":{isa:"C",xlens:1,fmt:"CJ-type",funct3:"001",immBits:[11,4,[9,8],10,6,7,[3,1],5],opcode:C_OPCODE.C1},"c.jr":{isa:"C",xlens:7,fmt:"CR-type",funct4:"1000",rdRs1Mask:1,rdRs1Excl:[0],rs2Val:0,opcode:C_OPCODE.C2},"c.jalr":{isa:"C",xlens:7,fmt:"CR-type",funct4:"1001",rdRs1Mask:1,rdRs1Excl:[0],rs2Val:0,opcode:C_OPCODE.C2},"c.beqz":{isa:"C",xlens:7,fmt:"CB-type",funct3:"110",immBits:[[8,[4,3]],[[7,6],[2,1],5]],opcode:C_OPCODE.C1},"c.bnez":{isa:"C",xlens:7,fmt:"CB-type",funct3:"111",immBits:[[8,[4,3]],[[7,6],[2,1],5]],opcode:C_OPCODE.C1},"c.li":{isa:"C",xlens:7,fmt:"CI-type",funct3:"010",rdRs1Mask:2,rdRs1Excl:[0],immBits:[[5],[[4,0]]],opcode:C_OPCODE.C1},"c.lui":{isa:"C",xlens:7,fmt:"CI-type",funct3:"011",rdRs1Mask:2,rdRs1Excl:[0,2],nzimm:!0,immBits:[[5],[[4,0]]],immBitsLabels:[[17],[[16,12]]],opcode:C_OPCODE.C1},"c.addi":{isa:"C",xlens:7,fmt:"CI-type",funct3:"000",rdRs1Mask:3,rdRs1Excl:[0],nzimm:!0,immBits:[[5],[[4,0]]],opcode:C_OPCODE.C1},"c.addiw":{isa:"C",xlens:6,fmt:"CI-type",funct3:"001",rdRs1Mask:3,rdRs1Excl:[0],immBits:[[5],[[4,0]]],opcode:C_OPCODE.C1},"c.addi16sp":{isa:"C",xlens:7,fmt:"CI-type",funct3:"011",rdRs1Mask:0,rdRs1Val:2,nzimm:!0,immBits:[[9],[4,6,[8,7],5]],opcode:C_OPCODE.C1},"c.slli":{isa:"C",xlens:7,fmt:"CI-type",funct3:"000",rdRs1Mask:3,rdRs1Excl:[0],nzimm:!0,uimm:!0,immBits:[[5],[[4,0]]],opcode:C_OPCODE.C2},"c.slli64":{isa:"C",xlens:4,fmt:"CI-type",funct3:"000",rdRs1Mask:3,rdRs1Excl:[0],immVal:0,immBits:[[5],[[4,0]]],opcode:C_OPCODE.C2},"c.addi4spn":{isa:"C",xlens:7,fmt:"CIW-type",funct3:"000",uimm:!0,nzimm:!0,immBits:[[5,4],[9,6],2,3],opcode:C_OPCODE.C0},"c.srli":{isa:"C",xlens:7,fmt:"CB-type",funct3:"100",funct2:"00",nzimm:!0,uimm:!0,immBits:[[5],[[4,0]]],opcode:C_OPCODE.C1},"c.srli64":{isa:"C",xlens:4,fmt:"CB-type",funct3:"100",funct2:"00",immVal:0,immBits:[[5],[[4,0]]],opcode:C_OPCODE.C1},"c.srai":{isa:"C",xlens:7,fmt:"CB-type",funct3:"100",funct2:"01",nzimm:!0,uimm:!0,immBits:[[5],[[4,0]]],opcode:C_OPCODE.C1},"c.srai64":{isa:"C",xlens:4,fmt:"CB-type",funct3:"100",funct2:"01",immVal:0,immBits:[[5],[[4,0]]],opcode:C_OPCODE.C1},"c.andi":{isa:"C",xlens:7,fmt:"CB-type",funct3:"100",funct2:"10",immBits:[[5],[[4,0]]],opcode:C_OPCODE.C1},"c.mv":{isa:"C",xlens:7,fmt:"CR-type",funct4:"1000",rdRs1Mask:2,rdRs1Excl:[0],rs2Excl:[0],opcode:C_OPCODE.C2},"c.add":{isa:"C",xlens:7,fmt:"CR-type",funct4:"1001",rdRs1Mask:3,rdRs1Excl:[0],rs2Excl:[0],opcode:C_OPCODE.C2},"c.and":{isa:"C",xlens:7,fmt:"CA-type",funct6:"100011",funct2:"11",opcode:C_OPCODE.C1},"c.or":{isa:"C",xlens:7,fmt:"CA-type",funct6:"100011",funct2:"10",opcode:C_OPCODE.C1},"c.xor":{isa:"C",xlens:7,fmt:"CA-type",funct6:"100011",funct2:"01",opcode:C_OPCODE.C1},"c.sub":{isa:"C",xlens:7,fmt:"CA-type",funct6:"100011",funct2:"00",opcode:C_OPCODE.C1},"c.subw":{isa:"C",xlens:6,fmt:"CA-type",funct6:"100111",funct2:"00",opcode:C_OPCODE.C1},"c.addw":{isa:"C",xlens:6,fmt:"CA-type",funct6:"100111",funct2:"01",opcode:C_OPCODE.C1},"c.nop":{isa:"C",xlens:7,fmt:"CI-type",funct3:"000",rdRs1Mask:0,rdRs1Val:0,immVal:0,immBits:[[5],[[4,0]]],opcode:C_OPCODE.C1},"c.ebreak":{isa:"C",xlens:7,fmt:"CR-type",funct4:"1001",rdRs1Mask:0,rdRs1Val:0,rs2Val:0,opcode:C_OPCODE.C2}};export const ISA_OP={[ISA_RV32I.add.funct7+ISA_RV32I.add.funct3]:"add",[ISA_RV32I.sub.funct7+ISA_RV32I.sub.funct3]:"sub",[ISA_RV32I.sll.funct7+ISA_RV32I.sll.funct3]:"sll",[ISA_RV32I.slt.funct7+ISA_RV32I.slt.funct3]:"slt",[ISA_RV32I.sltu.funct7+ISA_RV32I.sltu.funct3]:"sltu",[ISA_RV32I.xor.funct7+ISA_RV32I.xor.funct3]:"xor",[ISA_RV32I.srl.funct7+ISA_RV32I.srl.funct3]:"srl",[ISA_RV32I.sra.funct7+ISA_RV32I.sra.funct3]:"sra",[ISA_RV32I.or.funct7+ISA_RV32I.or.funct3]:"or",[ISA_RV32I.and.funct7+ISA_RV32I.and.funct3]:"and",[ISA_M.mul.funct7+ISA_M.mul.funct3]:"mul",[ISA_M.mulh.funct7+ISA_M.mulh.funct3]:"mulh",[ISA_M.mulhsu.funct7+ISA_M.mulhsu.funct3]:"mulhsu",[ISA_M.mulhu.funct7+ISA_M.mulhu.funct3]:"mulhu",[ISA_M.div.funct7+ISA_M.div.funct3]:"div",[ISA_M.divu.funct7+ISA_M.divu.funct3]:"divu",[ISA_M.rem.funct7+ISA_M.rem.funct3]:"rem",[ISA_M.remu.funct7+ISA_M.remu.funct3]:"remu"};export const ISA_OP_32={[ISA_RV64I.addw.funct7+ISA_RV64I.addw.funct3]:"addw",[ISA_RV64I.subw.funct7+ISA_RV64I.subw.funct3]:"subw",[ISA_RV64I.sllw.funct7+ISA_RV64I.sllw.funct3]:"sllw",[ISA_RV64I.srlw.funct7+ISA_RV64I.srlw.funct3]:"srlw",[ISA_RV64I.sraw.funct7+ISA_RV64I.sraw.funct3]:"sraw",[ISA_M.mulw.funct7+ISA_M.mulw.funct3]:"mulw",[ISA_M.divw.funct7+ISA_M.divw.funct3]:"divw",[ISA_M.divuw.funct7+ISA_M.divuw.funct3]:"divuw",[ISA_M.remw.funct7+ISA_M.remw.funct3]:"remw",[ISA_M.remuw.funct7+ISA_M.remuw.funct3]:"remuw"};export const ISA_OP_64={[ISA_RV128I.addd.funct7+ISA_RV128I.addd.funct3]:"addd",[ISA_RV128I.subd.funct7+ISA_RV128I.subd.funct3]:"subd",[ISA_RV128I.slld.funct7+ISA_RV128I.slld.funct3]:"slld",[ISA_RV128I.srld.funct7+ISA_RV128I.srld.funct3]:"srld",[ISA_RV128I.srad.funct7+ISA_RV128I.srad.funct3]:"srad",[ISA_M.muld.funct7+ISA_M.muld.funct3]:"muld",[ISA_M.divd.funct7+ISA_M.divd.funct3]:"divd",[ISA_M.divud.funct7+ISA_M.divud.funct3]:"divud",[ISA_M.remd.funct7+ISA_M.remd.funct3]:"remd",[ISA_M.remud.funct7+ISA_M.remud.funct3]:"remud"};export const ISA_LOAD={[ISA_RV32I.lb.funct3]:"lb",[ISA_RV32I.lh.funct3]:"lh",[ISA_RV32I.lw.funct3]:"lw",[ISA_RV64I.ld.funct3]:"ld",[ISA_RV32I.lbu.funct3]:"lbu",[ISA_RV32I.lhu.funct3]:"lhu",[ISA_RV64I.lwu.funct3]:"lwu",[ISA_RV128I.ldu.funct3]:"ldu"};export const ISA_STORE={[ISA_RV32I.sb.funct3]:"sb",[ISA_RV32I.sh.funct3]:"sh",[ISA_RV32I.sw.funct3]:"sw",[ISA_RV64I.sd.funct3]:"sd",[ISA_RV128I.sq.funct3]:"sq"};export const ISA_OP_IMM={[ISA_RV32I.addi.funct3]:"addi",[ISA_RV32I.slti.funct3]:"slti",[ISA_RV32I.sltiu.funct3]:"sltiu",[ISA_RV32I.xori.funct3]:"xori",[ISA_RV32I.ori.funct3]:"ori",[ISA_RV32I.andi.funct3]:"andi",[ISA_RV32I.slli.funct3]:"slli",[ISA_RV32I.srli.funct3]:{[ISA_RV32I.srli.shtyp]:"srli",[ISA_RV32I.srai.shtyp]:"srai"}};export const ISA_OP_IMM_32={[ISA_RV64I.addiw.funct3]:"addiw",[ISA_RV64I.slliw.funct3]:"slliw",[ISA_RV64I.srliw.funct3]:{[ISA_RV64I.srliw.shtyp]:"srliw",[ISA_RV64I.sraiw.shtyp]:"sraiw"}};export const ISA_OP_IMM_64={[ISA_RV128I.addid.funct3]:"addid",[ISA_RV128I.sllid.funct3]:"sllid",[ISA_RV128I.srlid.funct3]:{[ISA_RV128I.srlid.shtyp]:"srlid",[ISA_RV128I.sraid.shtyp]:"sraid"}};export const ISA_BRANCH={[ISA_RV32I.beq.funct3]:"beq",[ISA_RV32I.bne.funct3]:"bne",[ISA_RV32I.blt.funct3]:"blt",[ISA_RV32I.bge.funct3]:"bge",[ISA_RV32I.bltu.funct3]:"btlu",[ISA_RV32I.bgeu.funct3]:"bgeu"};export const ISA_MISC_MEM={[ISA_RV32I.fence.funct3]:"fence",[ISA_Zifencei["fence.i"].funct3]:"fence.i",[ISA_RV128I.lq.funct3]:"lq"};export const ISA_SYSTEM={[ISA_RV32I.ecall.funct3]:{[ISA_RV32I.ecall.funct12]:"ecall",[ISA_RV32I.ebreak.funct12]:"ebreak"},[ISA_Zicsr.csrrw.funct3]:"csrrw",[ISA_Zicsr.csrrs.funct3]:"csrrs",[ISA_Zicsr.csrrc.funct3]:"csrrc",[ISA_Zicsr.csrrwi.funct3]:"csrrwi",[ISA_Zicsr.csrrsi.funct3]:"csrrsi",[ISA_Zicsr.csrrci.funct3]:"csrrci"};export const ISA_AMO={[ISA_A["lr.w"].funct5+ISA_A["lr.w"].funct3]:"lr.w",[ISA_A["sc.w"].funct5+ISA_A["sc.w"].funct3]:"sc.w",[ISA_A["amoswap.w"].funct5+ISA_A["amoswap.w"].funct3]:"amoswap.w",[ISA_A["amoadd.w"].funct5+ISA_A["amoadd.w"].funct3]:"amoadd.w",[ISA_A["amoxor.w"].funct5+ISA_A["amoxor.w"].funct3]:"amoxor.w",[ISA_A["amoand.w"].funct5+ISA_A["amoand.w"].funct3]:"amoand.w",[ISA_A["amoor.w"].funct5+ISA_A["amoor.w"].funct3]:"amoor.w",[ISA_A["amomin.w"].funct5+ISA_A["amomin.w"].funct3]:"amomin.w",[ISA_A["amomax.w"].funct5+ISA_A["amomax.w"].funct3]:"amomax.w",[ISA_A["amominu.w"].funct5+ISA_A["amominu.w"].funct3]:"amominu.w",[ISA_A["amomaxu.w"].funct5+ISA_A["amomaxu.w"].funct3]:"amomaxu.w",[ISA_A["lr.d"].funct5+ISA_A["lr.d"].funct3]:"lr.d",[ISA_A["sc.d"].funct5+ISA_A["sc.d"].funct3]:"sc.d",[ISA_A["amoswap.d"].funct5+ISA_A["amoswap.d"].funct3]:"amoswap.d",[ISA_A["amoadd.d"].funct5+ISA_A["amoadd.d"].funct3]:"amoadd.d",[ISA_A["amoxor.d"].funct5+ISA_A["amoxor.d"].funct3]:"amoxor.d",[ISA_A["amoand.d"].funct5+ISA_A["amoand.d"].funct3]:"amoand.d",[ISA_A["amoor.d"].funct5+ISA_A["amoor.d"].funct3]:"amoor.d",[ISA_A["amomin.d"].funct5+ISA_A["amomin.d"].funct3]:"amomin.d",[ISA_A["amomax.d"].funct5+ISA_A["amomax.d"].funct3]:"amomax.d",[ISA_A["amominu.d"].funct5+ISA_A["amominu.d"].funct3]:"amominu.d",[ISA_A["amomaxu.d"].funct5+ISA_A["amomaxu.d"].funct3]:"amomaxu.d",[ISA_A["lr.q"].funct5+ISA_A["lr.q"].funct3]:"lr.q",[ISA_A["sc.q"].funct5+ISA_A["sc.q"].funct3]:"sc.q",[ISA_A["amoswap.q"].funct5+ISA_A["amoswap.q"].funct3]:"amoswap.q",[ISA_A["amoadd.q"].funct5+ISA_A["amoadd.q"].funct3]:"amoadd.q",[ISA_A["amoxor.q"].funct5+ISA_A["amoxor.q"].funct3]:"amoxor.q",[ISA_A["amoand.q"].funct5+ISA_A["amoand.q"].funct3]:"amoand.q",[ISA_A["amoor.q"].funct5+ISA_A["amoor.q"].funct3]:"amoor.q",[ISA_A["amomin.q"].funct5+ISA_A["amomin.q"].funct3]:"amomin.q",[ISA_A["amomax.q"].funct5+ISA_A["amomax.q"].funct3]:"amomax.q",[ISA_A["amominu.q"].funct5+ISA_A["amominu.q"].funct3]:"amominu.q",[ISA_A["amomaxu.q"].funct5+ISA_A["amomaxu.q"].funct3]:"amomaxu.q"};export const ISA_LOAD_FP={[FP_WIDTH.S]:"flw",[FP_WIDTH.D]:"fld",[FP_WIDTH.Q]:"flq"};export const ISA_STORE_FP={[FP_WIDTH.S]:"fsw",[FP_WIDTH.D]:"fsd",[FP_WIDTH.Q]:"fsq"};export const ISA_MADD={[FP_FMT.S]:"fmadd.s",[FP_FMT.D]:"fmadd.d",[FP_FMT.Q]:"fmadd.q"};export const ISA_MSUB={[FP_FMT.S]:"fmsub.s",[FP_FMT.D]:"fmsub.d",[FP_FMT.Q]:"fmsub.q"};export const ISA_NMADD={[FP_FMT.S]:"fnmadd.s",[FP_FMT.D]:"fnmadd.d",[FP_FMT.Q]:"fnmadd.q"};export const ISA_NMSUB={[FP_FMT.S]:"fnmsub.s",[FP_FMT.D]:"fnmsub.d",[FP_FMT.Q]:"fnmsub.q"};export const ISA_OP_FP={[ISA_F["fadd.s"].funct5]:{[FP_FMT.S]:"fadd.s",[FP_FMT.D]:"fadd.d",[FP_FMT.Q]:"fadd.q"},[ISA_F["fsub.s"].funct5]:{[FP_FMT.S]:"fsub.s",[FP_FMT.D]:"fsub.d",[FP_FMT.Q]:"fsub.q"},[ISA_F["fmul.s"].funct5]:{[FP_FMT.S]:"fmul.s",[FP_FMT.D]:"fmul.d",[FP_FMT.Q]:"fmul.q"},[ISA_F["fdiv.s"].funct5]:{[FP_FMT.S]:"fdiv.s",[FP_FMT.D]:"fdiv.d",[FP_FMT.Q]:"fdiv.q"},[ISA_F["fsqrt.s"].funct5]:{[FP_FMT.S]:"fsqrt.s",[FP_FMT.D]:"fsqrt.d",[FP_FMT.Q]:"fsqrt.q"},[ISA_F["fmv.w.x"].funct5]:{[FP_FMT.S]:"fmv.w.x",[FP_FMT.D]:"fmv.d.x",[FP_FMT.Q]:"fmv.q.x"},[ISA_F["fclass.s"].funct5]:{[FP_FMT.S]:{[ISA_F["fclass.s"].funct3]:"fclass.s",[ISA_F["fmv.x.w"].funct3]:"fmv.x.w"},[FP_FMT.D]:{[ISA_D["fclass.d"].funct3]:"fclass.d",[ISA_D["fmv.x.d"].funct3]:"fmv.x.d"},[FP_FMT.Q]:{[ISA_Q["fclass.q"].funct3]:"fclass.q",[ISA_Q["fmv.x.q"].funct3]:"fmv.x.q"}},[ISA_F["fsgnj.s"].funct5]:{[FP_FMT.S]:{[ISA_F["fsgnj.s"].funct3]:"fsgnj.s",[ISA_F["fsgnjn.s"].funct3]:"fsgnjn.s",[ISA_F["fsgnjx.s"].funct3]:"fsgnjx.s"},[FP_FMT.D]:{[ISA_D["fsgnj.d"].funct3]:"fsgnj.d",[ISA_D["fsgnjn.d"].funct3]:"fsgnjn.d",[ISA_D["fsgnjx.d"].funct3]:"fsgnjx.d"},[FP_FMT.Q]:{[ISA_Q["fsgnj.q"].funct3]:"fsgnj.q",[ISA_Q["fsgnjn.q"].funct3]:"fsgnjn.q",[ISA_Q["fsgnjx.q"].funct3]:"fsgnjx.q"}},[ISA_F["fmin.s"].funct5]:{[FP_FMT.S]:{[ISA_F["fmin.s"].funct3]:"fmin.s",[ISA_F["fmax.s"].funct3]:"fmax.s"},[FP_FMT.D]:{[ISA_D["fmin.d"].funct3]:"fmin.d",[ISA_D["fmax.d"].funct3]:"fmax.d"},[FP_FMT.Q]:{[ISA_Q["fmin.q"].funct3]:"fmin.q",[ISA_Q["fmax.q"].funct3]:"fmax.q"}},[ISA_F["feq.s"].funct5]:{[FP_FMT.S]:{[ISA_F["feq.s"].funct3]:"feq.s",[ISA_F["flt.s"].funct3]:"flt.s",[ISA_F["fle.s"].funct3]:"fle.s"},[FP_FMT.D]:{[ISA_D["feq.d"].funct3]:"feq.d",[ISA_D["flt.d"].funct3]:"flt.d",[ISA_D["fle.d"].funct3]:"fle.d"},[FP_FMT.Q]:{[ISA_Q["feq.q"].funct3]:"feq.q",[ISA_Q["flt.q"].funct3]:"flt.q",[ISA_Q["fle.q"].funct3]:"fle.q"}},[ISA_F["fcvt.w.s"].funct5]:{[FP_FMT.S]:{[ISA_F["fcvt.w.s"].rs2]:"fcvt.w.s",[ISA_F["fcvt.wu.s"].rs2]:"fcvt.wu.s",[ISA_F["fcvt.l.s"].rs2]:"fcvt.l.s",[ISA_F["fcvt.lu.s"].rs2]:"fcvt.lu.s",[ISA_F["fcvt.t.s"].rs2]:"fcvt.t.s",[ISA_F["fcvt.tu.s"].rs2]:"fcvt.tu.s"},[FP_FMT.D]:{[ISA_D["fcvt.w.d"].rs2]:"fcvt.w.d",[ISA_D["fcvt.wu.d"].rs2]:"fcvt.wu.d",[ISA_D["fcvt.l.d"].rs2]:"fcvt.l.d",[ISA_D["fcvt.lu.d"].rs2]:"fcvt.lu.d",[ISA_D["fcvt.t.d"].rs2]:"fcvt.t.d",[ISA_D["fcvt.tu.d"].rs2]:"fcvt.tu.d"},[FP_FMT.Q]:{[ISA_Q["fcvt.w.q"].rs2]:"fcvt.w.q",[ISA_Q["fcvt.wu.q"].rs2]:"fcvt.wu.q",[ISA_Q["fcvt.l.q"].rs2]:"fcvt.l.q",[ISA_Q["fcvt.lu.q"].rs2]:"fcvt.lu.q",[ISA_Q["fcvt.t.q"].rs2]:"fcvt.t.q",[ISA_Q["fcvt.tu.q"].rs2]:"fcvt.tu.q"}},[ISA_F["fcvt.s.w"].funct5]:{[FP_FMT.S]:{[ISA_F["fcvt.s.w"].rs2]:"fcvt.s.w",[ISA_F["fcvt.s.wu"].rs2]:"fcvt.s.wu",[ISA_F["fcvt.s.l"].rs2]:"fcvt.s.l",[ISA_F["fcvt.s.lu"].rs2]:"fcvt.s.lu",[ISA_F["fcvt.s.t"].rs2]:"fcvt.s.t",[ISA_F["fcvt.s.tu"].rs2]:"fcvt.s.tu"},[FP_FMT.D]:{[ISA_D["fcvt.d.w"].rs2]:"fcvt.d.w",[ISA_D["fcvt.d.wu"].rs2]:"fcvt.d.wu",[ISA_D["fcvt.d.l"].rs2]:"fcvt.d.l",[ISA_D["fcvt.d.lu"].rs2]:"fcvt.d.lu",[ISA_D["fcvt.d.t"].rs2]:"fcvt.d.t",[ISA_D["fcvt.d.tu"].rs2]:"fcvt.d.tu"},[FP_FMT.Q]:{[ISA_Q["fcvt.q.w"].rs2]:"fcvt.q.w",[ISA_Q["fcvt.q.wu"].rs2]:"fcvt.q.wu",[ISA_Q["fcvt.q.l"].rs2]:"fcvt.q.l",[ISA_Q["fcvt.q.lu"].rs2]:"fcvt.q.lu",[ISA_Q["fcvt.q.t"].rs2]:"fcvt.q.t",[ISA_Q["fcvt.q.tu"].rs2]:"fcvt.q.tu"}},[ISA_D["fcvt.s.d"].funct5]:{[FP_FMT.S]:{[ISA_D["fcvt.s.d"].rs2]:"fcvt.s.d",[ISA_Q["fcvt.s.q"].rs2]:"fcvt.s.q"},[FP_FMT.D]:{[ISA_D["fcvt.d.s"].rs2]:"fcvt.d.s",[ISA_Q["fcvt.d.q"].rs2]:"fcvt.d.q"},[FP_FMT.Q]:{[ISA_Q["fcvt.q.s"].rs2]:"fcvt.q.s",[ISA_Q["fcvt.q.d"].rs2]:"fcvt.q.d"}}};function t(...t){let f={};for(const c of t){const t=ISA_C[c];for(let m=XLEN_MASK.rv32;m<=XLEN_MASK.all;m<<=1)t.xlens&m&&(f[m]=c)}return f}export const ISA_C0={[ISA_C["c.addi4spn"].funct3]:"c.addi4spn",[ISA_C["c.fld"].funct3]:t("c.fld","c.lq"),[ISA_C["c.lw"].funct3]:"c.lw",[ISA_C["c.flw"].funct3]:t("c.flw","c.ld"),[ISA_C["c.fsd"].funct3]:t("c.fsd","c.sq"),[ISA_C["c.sw"].funct3]:"c.sw",[ISA_C["c.fsw"].funct3]:t("c.fsw","c.sd")};export const ISA_C1={[ISA_C["c.nop"].funct3]:{[XLEN_MASK.all]:{[ISA_C["c.nop"].rdRs1Val]:"c.nop",default:"c.addi"}},[ISA_C["c.jal"].funct3]:t("c.jal","c.addiw"),[ISA_C["c.li"].funct3]:"c.li",[ISA_C["c.addi16sp"].funct3]:{[XLEN_MASK.all]:{[ISA_C["c.addi16sp"].rdRs1Val]:"c.addi16sp",default:"c.lui"}},[ISA_C["c.srli"].funct3]:{[XLEN_MASK.all]:{default:{[ISA_C["c.srli"].funct2]:"c.srli",[ISA_C["c.srai"].funct2]:"c.srai",[ISA_C["c.andi"].funct2]:"c.andi",11:{[ISA_C["c.sub"].funct6[3]+ISA_C["c.sub"].funct2]:"c.sub",[ISA_C["c.xor"].funct6[3]+ISA_C["c.xor"].funct2]:"c.xor",[ISA_C["c.or"].funct6[3]+ISA_C["c.or"].funct2]:"c.or",[ISA_C["c.and"].funct6[3]+ISA_C["c.and"].funct2]:"c.and",[ISA_C["c.subw"].funct6[3]+ISA_C["c.subw"].funct2]:"c.subw",[ISA_C["c.addw"].funct6[3]+ISA_C["c.addw"].funct2]:"c.addw"}}}},[ISA_C["c.j"].funct3]:"c.j",[ISA_C["c.beqz"].funct3]:"c.beqz",[ISA_C["c.bnez"].funct3]:"c.bnez"};export const ISA_C2={[ISA_C["c.slli"].funct3]:"c.slli",[ISA_C["c.fldsp"].funct3]:t("c.fldsp","c.lqsp"),[ISA_C["c.lwsp"].funct3]:"c.lwsp",[ISA_C["c.flwsp"].funct3]:t("c.flwsp","c.ldsp"),[ISA_C["c.jr"].funct4.substring(0,3)]:{[XLEN_MASK.all]:{[ISA_C["c.jr"].funct4[3]]:{[ISA_C["c.jr"].rs2Val]:"c.jr",default:"c.mv"},[ISA_C["c.ebreak"].funct4[3]]:{[ISA_C["c.ebreak"].rs2Val]:{[ISA_C["c.ebreak"].rdRs1Val]:"c.ebreak",default:"c.jalr"},default:"c.add"}}},[ISA_C["c.fsdsp"].funct3]:t("c.fsdsp","c.sqsp"),[ISA_C["c.swsp"].funct3]:"c.swsp",[ISA_C["c.fswsp"].funct3]:t("c.fswsp","c.sdsp")};export const REGISTER={zero:"x0",ra:"x1",sp:"x2",gp:"x3",tp:"x4",t0:"x5",t1:"x6",t2:"x7",s0:"x8",s1:"x9",a0:"x10",a1:"x11",a2:"x12",a3:"x13",a4:"x14",a5:"x15",a6:"x16",a7:"x17",s2:"x18",s3:"x19",s4:"x20",s5:"x21",s6:"x22",s7:"x23",s8:"x24",s9:"x25",s10:"x26",s11:"x27",t3:"x28",t4:"x29",t5:"x30",t6:"x31",fp:"x8"};export const FLOAT_REGISTER={ft0:"f0",ft1:"f1",ft2:"f2",ft3:"f3",ft4:"f4",ft5:"f5",ft6:"f6",ft7:"f7",fs0:"f8",fs1:"f9",fa0:"f10",fa1:"f11",fa2:"f12",fa3:"f13",fa4:"f14",fa5:"f15",fa6:"f16",fa7:"f17",fs2:"f18",fs3:"f19",fs4:"f20",fs5:"f21",fs6:"f22",fs7:"f23",fs8:"f24",fs9:"f25",fs10:"f26",fs11:"f27",ft8:"f28",ft9:"f29",ft10:"f30",ft11:"f31"};export const CSR={cycle:3072,cycleh:3200,dcsr:1968,dpc:1969,dscratch0:1970,dscratch1:1971,fcsr:3,fflags:1,frm:2,hcounteren:1542,hedeleg:1538,hgatp:1664,hgeie:1543,hgeip:3591,hideleg:1539,hie:1540,hip:1604,hpmcounter3:3075,hpmcounter4:3076,hpmcounter5:3077,hpmcounter6:3078,hpmcounter7:3079,hpmcounter8:3080,hpmcounter9:3081,hpmcounter10:3082,hpmcounter11:3083,hpmcounter12:3084,hpmcounter13:3085,hpmcounter14:3086,hpmcounter15:3087,hpmcounter16:3088,hpmcounter17:3089,hpmcounter18:3090,hpmcounter19:3091,hpmcounter20:3092,hpmcounter21:3093,hpmcounter22:3094,hpmcounter23:3095,hpmcounter24:3096,hpmcounter25:3097,hpmcounter26:3098,hpmcounter27:3099,hpmcounter28:3100,hpmcounter29:3101,hpmcounter30:3102,hpmcounter31:3103,hpmcounter3h:3203,hpmcounter4h:3204,hpmcounter5h:3205,hpmcounter6h:3206,hpmcounter7h:3207,hpmcounter8h:3208,hpmcounter9h:3209,hpmcounter10h:3210,hpmcounter11h:3211,hpmcounter12h:3212,hpmcounter13h:3213,hpmcounter14h:3214,hpmcounter15h:3215,hpmcounter16h:3216,hpmcounter17h:3217,hpmcounter18h:3218,hpmcounter19h:3219,hpmcounter20h:3220,hpmcounter21h:3221,hpmcounter22h:3222,hpmcounter23h:3223,hpmcounter24h:3224,hpmcounter25h:3225,hpmcounter26h:3226,hpmcounter27h:3227,hpmcounter28h:3228,hpmcounter29h:3229,hpmcounter30h:3230,hpmcounter31h:3231,hstatus:1536,htimedelta:1541,htimedeltah:1557,htinst:1610,htval:1603,instret:3074,instreth:3202,marchid:3858,mbase:896,mbound:897,mcause:834,mcounteren:774,mcountinhibit:800,mcycle:2816,mcycleh:2944,mdbase:900,mdbound:901,medeleg:770,mepc:833,mhartid:3860,mhpmcounter3:2819,mhpmcounter4:2820,mhpmcounter5:2821,mhpmcounter6:2822,mhpmcounter7:2823,mhpmcounter8:2824,mhpmcounter9:2825,mhpmcounter10:2826,mhpmcounter11:2827,mhpmcounter12:2828,mhpmcounter13:2829,mhpmcounter14:2830,mhpmcounter15:2831,mhpmcounter16:2832,mhpmcounter17:2833,mhpmcounter18:2834,mhpmcounter19:2835,mhpmcounter20:2836,mhpmcounter21:2837,mhpmcounter22:2838,mhpmcounter23:2839,mhpmcounter24:2840,mhpmcounter25:2841,mhpmcounter26:2842,mhpmcounter27:2843,mhpmcounter28:2844,mhpmcounter29:2845,mhpmcounter30:2846,mhpmcounter31:2847,mhpmcounter3h:2947,mhpmcounter4h:2948,mhpmcounter5h:2949,mhpmcounter6h:2950,mhpmcounter7h:2951,mhpmcounter8h:2952,mhpmcounter9h:2953,mhpmcounter10h:2954,mhpmcounter11h:2955,mhpmcounter12h:2956,mhpmcounter13h:2957,mhpmcounter14h:2958,mhpmcounter15h:2959,mhpmcounter16h:2960,mhpmcounter17h:2961,mhpmcounter18h:2962,mhpmcounter19h:2963,mhpmcounter20h:2964,mhpmcounter21h:2965,mhpmcounter22h:2966,mhpmcounter23h:2967,mhpmcounter24h:2968,mhpmcounter25h:2969,mhpmcounter26h:2970,mhpmcounter27h:2971,mhpmcounter28h:2972,mhpmcounter29h:2973,mhpmcounter30h:2974,mhpmcounter31h:2975,mhpmevent3:803,mhpmevent4:804,mhpmevent5:805,mhpmevent6:806,mhpmevent7:807,mhpmevent8:808,mhpmevent9:809,mhpmevent10:810,mhpmevent11:811,mhpmevent12:812,mhpmevent13:813,mhpmevent14:814,mhpmevent15:815,mhpmevent16:816,mhpmevent17:817,mhpmevent18:818,mhpmevent19:819,mhpmevent20:820,mhpmevent21:821,mhpmevent22:822,mhpmevent23:823,mhpmevent24:824,mhpmevent25:825,mhpmevent26:826,mhpmevent27:827,mhpmevent28:828,mhpmevent29:829,mhpmevent30:830,mhpmevent31:831,mibase:898,mibound:899,mideleg:771,mie:772,mimpid:3859,minstret:2818,minstreth:2946,mip:836,misa:769,mscratch:832,mstatus:768,mstatush:784,mtinst:842,mtval:835,mtval2:843,mtvec:773,mvendorid:3857,pmpaddr0:944,pmpaddr1:945,pmpaddr2:946,pmpaddr3:947,pmpaddr4:948,pmpaddr5:949,pmpaddr6:950,pmpaddr7:951,pmpaddr8:952,pmpaddr9:953,pmpaddr10:954,pmpaddr11:955,pmpaddr12:956,pmpaddr13:957,pmpaddr14:958,pmpaddr15:959,pmpaddr16:960,pmpaddr17:961,pmpaddr18:962,pmpaddr19:963,pmpaddr20:964,pmpaddr21:965,pmpaddr22:966,pmpaddr23:967,pmpaddr24:968,pmpaddr25:969,pmpaddr26:970,pmpaddr27:971,pmpaddr28:972,pmpaddr29:973,pmpaddr30:974,pmpaddr31:975,pmpaddr32:976,pmpaddr33:977,pmpaddr34:978,pmpaddr35:979,pmpaddr36:980,pmpaddr37:981,pmpaddr38:982,pmpaddr39:983,pmpaddr40:984,pmpaddr41:985,pmpaddr42:986,pmpaddr43:987,pmpaddr44:988,pmpaddr45:989,pmpaddr46:990,pmpaddr47:991,pmpaddr48:992,pmpaddr49:993,pmpaddr50:994,pmpaddr51:995,pmpaddr52:996,pmpaddr53:997,pmpaddr54:998,pmpaddr55:999,pmpaddr56:1e3,pmpaddr57:1001,pmpaddr58:1002,pmpaddr59:1003,pmpaddr60:1004,pmpaddr61:1005,pmpaddr62:1006,pmpaddr63:1007,pmpcfg0:928,pmpcfg1:929,pmpcfg2:930,pmpcfg3:931,pmpcfg4:932,pmpcfg5:933,pmpcfg6:934,pmpcfg7:935,pmpcfg8:936,pmpcfg9:937,pmpcfg10:938,pmpcfg11:939,pmpcfg12:940,pmpcfg13:941,pmpcfg14:942,pmpcfg15:943,satp:384,scause:322,scounteren:262,sedeleg:258,sepc:321,sideleg:259,sie:260,sip:324,sscratch:320,sstatus:256,stval:323,stvec:261,tdata1:1953,tdata2:1954,tdata3:1955,time:3073,timeh:3201,tselect:1952,ucause:66,uepc:65,uie:4,uip:68,uscratch:64,ustatus:0,utval:67,utvec:5,vsatp:640,vscause:578,vsepc:577,vsie:516,vsip:580,vsscratch:576,vsstatus:512,vstval:579,vstvec:517};export const FRAG={UNSD:1,CSR:2,IMM:3,OPC:4,PRED:5,RD:6,RS1:7,RS2:8,RS3:9,SUCC:10};export const ISA=Object.assign({},ISA_RV32I,ISA_RV64I,ISA_RV128I,ISA_Zifencei,ISA_Zicsr,ISA_M,ISA_A,ISA_F,ISA_D,ISA_Q,ISA_C);
✄
export function decRegAbi(regDec: any, floatReg?: boolean): string;
export class Decoder {
    /**
     * Creates an Decoder to convert a binary instruction to assembly
     * @param {String} bin
     */
    constructor(bin: string, config: any, xlens?: undefined);
    /**
     * Assembly representation of instruction
     * @type String
     */
    asm: string;
    /**
     * ISA of instruction: 'RV32I', 'RV64I', 'EXT_M', 'EXT_A', etc.
     * @type String
     */
    isa: string;
    /**
     * Format of instruction: 'R-type', 'I-type', etc.
     * @type String
     */
    fmt: string;
    /**
     * Fragments for binary instruction rendering
     * @type {Frag[]}
     */
    binFrags: Frag[];
    /**
     * Fragments for assembly instruction rendering
     * @type {Frag[]}
     */
    asmfrags: Frag[];
    asmFrags: any[];
    #private;
}
import { Frag } from './Instruction.js';

✄
var s,t,i,e,n,r,m,c,o,f,h,a,d,_,u,p,l,w,b,M,v,g,P,O,C,R,I,F,S,D,k,y,A=this&&this.__classPrivateFieldSet||function(s,t,i,e,n){if("m"===e)throw new TypeError("Private method is not writable");if("a"===e&&!n)throw new TypeError("Private accessor was defined without a setter");if("function"==typeof t?s!==t||!n:!t.has(s))throw new TypeError("Cannot write private member to an object whose class did not declare it");return"a"===e?n.call(s,i):n?n.value=i:t.set(s,i),i},B=this&&this.__classPrivateFieldGet||function(s,t,i,e){if("a"===i&&!e)throw new TypeError("Private accessor was defined without a getter");if("function"==typeof t?s!==t||!e:!t.has(s))throw new TypeError("Cannot read private member from an object whose class did not declare it");return"m"===i?e:"a"===i?e.call(s):e?e.value:t.get(s)};import{BASE as j,XLEN_MASK as V,FIELDS as E,OPCODE as $,C_OPCODE as x,REGISTER as z,FLOAT_REGISTER as T,CSR as N,ISA_OP as U,ISA_OP_32 as q,ISA_OP_64 as L,ISA_OP_IMM as W,ISA_OP_IMM_32 as H,ISA_OP_IMM_64 as J,ISA_LOAD as Y,ISA_STORE as G,ISA_BRANCH as K,ISA_MISC_MEM as Q,ISA_SYSTEM as X,ISA_AMO as Z,ISA_LOAD_FP as ss,ISA_STORE_FP as ts,ISA_OP_FP as is,ISA_MADD as es,ISA_MSUB as ns,ISA_NMADD as rs,ISA_NMSUB as ms,ISA_C0 as cs,ISA_C1 as os,ISA_C2 as fs,ISA as hs,FRAG as as}from"./Constants.js";import{COPTS_ISA as ds}from"./Config.js";import{Frag as _s,convertRegToAbi as us}from"./Instruction.js";export class Decoder{constructor(c,o,f){s.add(this),t.set(this,void 0),i.set(this,void 0),e.set(this,void 0),n.set(this,void 0),r.set(this,void 0),A(this,t,c,"f"),A(this,i,o,"f"),A(this,r,f,"f"),this.binFrags=[],this.asmFrags=[],B(this,s,"m",m).call(this)}}function ps(s){return{rs2:bs(s,E.rs2.pos),rs1:bs(s,E.rs1.pos),funct3:bs(s,E.funct3.pos),rd:bs(s,E.rd.pos),funct5:bs(s,E.r_funct5.pos),funct7:bs(s,E.r_funct7.pos),aq:bs(s,E.r_aq.pos),rl:bs(s,E.r_rl.pos),fmt:bs(s,E.r_fp_fmt.pos)}}function ls(s){return{imm:bs(s,E.i_imm_11_0.pos),rs1:bs(s,E.rs1.pos),funct3:bs(s,E.funct3.pos),rd:bs(s,E.rd.pos),shtyp:bs(s,E.i_shtyp.pos),shamt:bs(s,E.i_shamt.pos),shamt_5:bs(s,E.i_shamt_5.pos),shamt_6:bs(s,E.i_shamt_6.pos),funct12:bs(s,E.i_funct12.pos),fm:bs(s,E.i_fm.pos),pred:bs(s,E.i_pred.pos),succ:bs(s,E.i_succ.pos)}}function ws(s){return{funct6:bs(s,E.c_funct6.pos),funct4:bs(s,E.c_funct4.pos),funct3:bs(s,E.c_funct3.pos),funct2:bs(s,E.c_funct2.pos),funct2_cb:bs(s,E.c_funct2_cb.pos),rd_rs1:bs(s,E.c_rd_rs1.pos),rs2:bs(s,E.c_rs2.pos)}}function bs(s,t){if(!Array.isArray(t))throw bs.name+": position should be an array";let i=t[0]+1,e=i-t[1];if(e>i||s.length<i)throw bs.name+": position error";return s.substring(s.length-i,s.length-e)}function Ms(s,t=!0){return t&&"1"===s[0]?parseInt(s,j.bin)-Number("0b1"+"".padStart(s.length,"0")):parseInt(s,j.bin)}function vs(s,t,i=!1){var e;let n="".padStart(18,"0").split(""),r=0;"string"==typeof s&&(s=[s],t=[t]);for(let i=0;i<s.length;i++){const m=s[i],c=t[i];let o=0;for(let s=0;s<c.length;s++){let t=c[s];if(r=Math.max(r,null!==(e=null==t?void 0:t[0])&&void 0!==e?e:t),"number"==typeof t)n[17-t]=m[o],o++;else{const s=t[0],i=s-t[1]+1;for(let t=0;t<i;t++,o++)n[17-s+t]=m[o]}}}let m=n.join("");const c=!i;return c&&(m=m.substring(18-r-1)),Ms(m,c)}function gs(s,t=!1){return(t?"f":"x")+parseInt(s,j.bin)}t=new WeakMap,i=new WeakMap,e=new WeakMap,n=new WeakMap,r=new WeakMap,s=new WeakSet,m=function(){var m,j;if(A(this,n,bs(B(this,t,"f"),E.opcode.pos),"f"),"11"===B(this,n,"f").substring(B(this,n,"f").length-2))switch(B(this,n,"f")){case $.OP:case $.OP_32:case $.OP_64:B(this,s,"m",c).call(this);break;case $.OP_FP:B(this,s,"m",o).call(this);break;case $.AMO:B(this,s,"m",b).call(this);break;case $.JALR:B(this,s,"m",f).call(this);break;case $.LOAD:case $.LOAD_FP:B(this,s,"m",h).call(this);break;case $.OP_IMM:case $.OP_IMM_32:case $.OP_IMM_64:B(this,s,"m",a).call(this);break;case $.MISC_MEM:B(this,s,"m",d).call(this);break;case $.SYSTEM:B(this,s,"m",_).call(this);break;case $.STORE:case $.STORE_FP:B(this,s,"m",u).call(this);break;case $.BRANCH:B(this,s,"m",p).call(this);break;case $.LUI:case $.AUIPC:B(this,s,"m",l).call(this);break;case $.JAL:B(this,s,"m",w).call(this);break;case $.MADD:case $.MSUB:case $.NMADD:case $.NMSUB:B(this,s,"m",M).call(this);break;default:throw"Invalid opcode: "+B(this,n,"f")}else{if(void 0===B(this,r,"f"))switch(B(this,i,"f").ISA){case ds.RV128I:A(this,r,V.rv128,"f");break;case ds.RV64I:A(this,r,V.rv64,"f");break;default:A(this,r,V.rv32,"f")}else for(let s=1;s<V.all;s<<=1)if(s&B(this,r,"f")){A(this,r,s,"f");break}let c,o;switch(A(this,n,bs(B(this,t,"f"),E.c_opcode.pos),"f"),B(this,n,"f")){case x.C0:c=B(this,s,"m",v).call(this),o="C0";break;case x.C1:c=B(this,s,"m",g).call(this),o="C1";break;case x.C2:c=B(this,s,"m",P).call(this),o="C2";break;default:throw`Cannot decode binary instruction: ${this.bin}`}if(void 0===c)throw`Detected quadrant ${o} but could not determine instruction, potentially HINT or reserved`;c.xlens&V.rv32?this.isa="RV32":c.xlens&V.rv64?this.isa="RV64":this.isa="RV128",this.isa+=c.isa;switch(null===(m=/^([^-]+)-/.exec(null==c?void 0:c.fmt))||void 0===m?void 0:m[1]){case"CR":B(this,s,"m",O).call(this,c);break;case"CI":B(this,s,"m",C).call(this,c);break;case"CSS":B(this,s,"m",R).call(this,c);break;case"CIW":B(this,s,"m",I).call(this,c);break;case"CL":B(this,s,"m",F).call(this,c);break;case"CS":B(this,s,"m",S).call(this,c);break;case"CA":B(this,s,"m",D).call(this,c);break;case"CB":B(this,s,"m",k).call(this,c);break;case"CJ":B(this,s,"m",y).call(this,c);break;default:throw`Internal error: Detected ${B(this,e,"f")} in quadrant ${o} but could not match instruction format`}}if(void 0===typeof B(this,e,"f"))throw"Decoder internal error";if(this.fmt=hs[B(this,e,"f")].fmt,this.isa=null!==(j=this.isa)&&void 0!==j?j:hs[B(this,e,"f")].isa,B(this,i,"f").ISA===ds.RV32I&&/^RV(?:64|128)/.test(this.isa))throw`Detected ${this.isa} instruction but configuration ISA set to RV32I`;if(B(this,i,"f").ISA===ds.RV64I&&/^RV128/.test(this.isa))throw`Detected ${this.isa} instruction but configuration ISA set to RV64I`;this.asm=function(s,t=!1){let i=s[0].asm;for(let e=1;e<s.length;e++){let n=t?us(s[e].asm):s[e].asm;1===e?i+=" ":s[e].mem&&/^(?:nz)?(?:u)?imm/.test(s[e-1].field)||(i+=", "),s[e].mem?i+="("+n+")":i+=n}return i.trim()}(this.asmFrags,B(this,i,"f").ABI)},c=function(){const s=ps(B(this,t,"f")),i=s.funct7,r=s.funct3,m=s.rs2,c=s.rs1,o=s.rd;let f;if(B(this,n,"f")===$.OP_64?(A(this,e,L[i+r],"f"),f="OP-64"):B(this,n,"f")===$.OP_32?(A(this,e,q[i+r],"f"),f="OP-32"):(A(this,e,U[i+r],"f"),f="OP"),void 0===B(this,e,"f"))throw`Detected ${f} instruction but invalid funct7 and funct3 fields`;const h=gs(c),a=gs(m),d=gs(o),_={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),r,E.funct3.name),funct7:new _s(as.OPC,B(this,e,"f"),i,E.r_funct7.name),rd:new _s(as.RD,d,o,E.rd.name),rs1:new _s(as.RS1,h,c,E.rs1.name),rs2:new _s(as.RS2,a,m,E.rs2.name)};this.asmFrags.push(_.opcode,_.rd,_.rs1,_.rs2),this.binFrags.push(_.funct7,_.rs2,_.rs1,_.funct3,_.rd,_.opcode)},o=function(){var s;const i=ps(B(this,t,"f")),r=i.funct5,m=i.funct3,c=i.fmt,o=i.rs2,f=i.rs1,h=i.rd;if(A(this,e,null===(s=is[r])||void 0===s?void 0:s[c],"f"),void 0!==B(this,e,"f")&&"string"!=typeof B(this,e,"f")&&(void 0!==B(this,e,"f")[o]?A(this,e,B(this,e,"f")[o],"f"):A(this,e,B(this,e,"f")[m],"f")),void 0===B(this,e,"f"))throw"Detected OP-FP instruction but invalid funct and fmt fields";const a=hs[B(this,e,"f")],d=void 0===a.rs2;let _=!0,u=!0;"1"===r[0]&&("1"===r[3]?u=!1:_=!1);const p=gs(f,u),l=gs(o,!0),w=gs(h,_),b=void 0===a.funct3,M={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),m,b?"rm":E.funct3.name),funct5:new _s(as.OPC,B(this,e,"f"),r,E.r_funct5.name),fmt:new _s(as.OPC,B(this,e,"f"),c,E.r_fp_fmt.name),rd:new _s(as.RD,w,h,E.rd.name),rs1:new _s(as.RS1,p,f,E.rs1.name),rs2:new _s(as.OPC,l,o,E.rs2.name)};this.asmFrags.push(M.opcode,M.rd,M.rs1),d&&(M.rs2.id=as.RS2,this.asmFrags.push(M.rs2)),this.binFrags.push(M.funct5,M.fmt,M.rs2,M.rs1,M.funct3,M.rd,M.opcode)},f=function(){const s=ls(B(this,t,"f")),i=s.imm,r=s.rs1,m=s.funct3,c=s.rd;A(this,e,"jalr","f");const o=gs(r),f=gs(c),h=Ms(i),a={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),m,E.funct3.name),rd:new _s(as.RD,f,c,E.rd.name),rs1:new _s(as.RS1,o,r,E.rs1.name),imm:new _s(as.IMM,h,i,E.i_imm_11_0.name)};this.asmFrags.push(a.opcode,a.rd,a.rs1,a.imm),this.binFrags.push(a.imm,a.rs1,a.funct3,a.rd,a.opcode)},h=function(){const s=ls(B(this,t,"f")),i=s.imm,r=s.rs1,m=s.funct3,c=s.rd,o=B(this,n,"f")===$.LOAD_FP;if(A(this,e,o?ss[m]:Y[m],"f"),void 0===B(this,e,"f"))throw`Detected LOAD${o?"-FP":""} instruction but invalid funct3 field`;const f=gs(r),h=gs(c,o),a=Ms(i),d={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),m,E.funct3.name),rd:new _s(as.RD,h,c,E.rd.name),rs1:new _s(as.RS1,f,r,E.rs1.name,!0),imm:new _s(as.IMM,a,i,E.i_imm_11_0.name)};this.asmFrags.push(d.opcode,d.rd,d.imm,d.rs1),this.binFrags.push(d.imm,d.rs1,d.funct3,d.rd,d.opcode)},a=function(){var s;const r=ls(B(this,t,"f")),m=r.imm,c=r.rs1,o=r.funct3,f=r.rd;let h;const a=B(this,n,"f")===$.OP_IMM_32,d=B(this,n,"f")===$.OP_IMM_64;if(d?(A(this,e,J[o],"f"),h="OP-IMM-64"):a?(A(this,e,H[o],"f"),h="OP-IMM-32"):(A(this,e,W[o],"f"),h="OP-IMM"),void 0===B(this,e,"f"))throw`Detected ${h} instruction but invalid funct3 field`;let _;"string"!=typeof B(this,e,"f")?(_=!0,A(this,e,B(this,e,"f")[r.shtyp],"f")):_=o===hs.slli.funct3;const u=gs(c),p=gs(f),l={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),o,E.funct3.name),rd:new _s(as.RD,p,f,E.rd.name),rs1:new _s(as.RS1,u,c,E.rs1.name)};if(_){const t=r.shtyp,n=r.shamt_6,c=r.shamt_5,o=r.shamt,f="0"+t+"000",h=f+"0",_=h+"0",u=Ms(n+(c+o),!1);let p;if(a?p=5:d?(p=6,this.isa="RV128I"):p=B(this,i,"f").ISA===ds.RV32I||"0"===n&&"0"===c?5:B(this,i,"f").ISA===ds.RV64I||"0"===n?6:7,u>=32&&5===p)throw`Invalid shamt field: ${u} (out of range for opcode or ISA config)`;if(u>=64&&6===p)throw`Invalid shamt field: ${u} (out of range for opcode or ISA config)`;if(7===p){const s=n+c+o;l.imm=new _s(as.IMM,u,s,E.i_shamt_6_0.name),l.shift=new _s(as.OPC,B(this,e,"f"),f,E.i_shtyp_11_7.name),this.isa="RV128I"}else if(6===p){const t=c+o;l.imm=new _s(as.IMM,u,t,E.i_shamt_5_0.name),l.shift=new _s(as.OPC,B(this,e,"f"),h,E.i_shtyp_11_6.name),this.isa=null!==(s=this.isa)&&void 0!==s?s:"RV64I"}else l.imm=new _s(as.IMM,u,o,E.i_shamt.name),l.shift=new _s(as.OPC,B(this,e,"f"),_,E.i_shtyp_11_5.name);if(5===p&&_!==m.substring(0,7)||6===p&&h!==m.substring(0,6)||7===p&&f!==m.substring(0,5))throw`Detected ${this.isa} shift immediate instruction but invalid shtyp field`;this.binFrags.push(l.shift,l.imm,l.rs1,l.funct3,l.rd,l.opcode)}else{const s=r.imm,t=Ms(s);l.imm=new _s(as.IMM,t,s,E.i_imm_11_0.name),this.binFrags.push(l.imm,l.rs1,l.funct3,l.rd,l.opcode)}this.asmFrags.push(l.opcode,l.rd,l.rs1,l.imm)},d=function(){const s=ls(B(this,t,"f")),i=s.imm,r=s.fm,m=s.pred,c=s.succ,o=s.rs1,f=s.funct3,h=s.rd;if(A(this,e,Q[f],"f"),void 0===B(this,e,"f"))throw"Detected MISC-MEM instruction but invalid funct3 field";let a="lq"===B(this,e,"f");if(!a&&("00000"!==h||"00000"!==o))throw"Registers rd and rs1 should be 0";const d={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),f,E.funct3.name)};if(a){const s=Ms(i),t=gs(o),e=gs(h);d.imm=new _s(as.IMM,s,i,E.i_imm_11_0.name),d.rs1=new _s(as.RS1,t,o,E.rs1.name,!0),d.rd=new _s(as.RD,e,h,E.rd.name),this.asmFrags.push(d.opcode,d.rd,d.imm,d.rs1),this.binFrags.push(d.imm,d.rs1,d.funct3,d.rd,d.opcode)}else if("fence"===B(this,e,"f")){let s=Ps(m),t=Ps(c);d.fm=new _s(as.OPC,B(this,e,"f"),r,E.i_fm.name),d.pred=new _s(as.PRED,s,m,E.i_pred.name),d.succ=new _s(as.SUCC,t,c,E.i_succ.name),d.rd=new _s(as.OPC,B(this,e,"f"),h,E.rd.name),d.rs1=new _s(as.OPC,B(this,e,"f"),o,E.rs1.name,a),this.asmFrags.push(d.opcode,d.pred,d.succ),this.binFrags.push(d.fm,d.pred,d.succ,d.rs1,d.funct3,d.rd,d.opcode)}else"fence.i"===B(this,e,"f")&&(d.imm=new _s(as.UNSD,B(this,e,"f"),i,E.i_imm_11_0.name),d.rs1=new _s(as.UNSD,B(this,e,"f"),o,E.rs1.name),d.rd=new _s(as.UNSD,B(this,e,"f"),h,E.rd.name),this.asmFrags.push(d.opcode),this.binFrags.push(d.imm,d.rs1,d.funct3,d.rd,d.opcode))},_=function(){const s=ls(B(this,t,"f")),i=s.imm,r=s.rs1,m=s.funct3,c=s.rd;if(A(this,e,X[m],"f"),void 0===B(this,e,"f"))throw"Detected SYSTEM instruction but invalid funct3 field";let o="string"!=typeof B(this,e,"f");if(o){if(A(this,e,B(this,e,"f")[i],"f"),void 0===B(this,e,"f"))throw"Detected SYSTEM instruction but invalid funct12 field";if("00000"!==c||"00000"!==r)throw"Registers rd and rs1 should be 0 for mne "+B(this,e,"f")}const f={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),m,E.funct3.name)};if(o)f.rd=new _s(as.OPC,B(this,e,"f"),c,E.rd.name),f.rs1=new _s(as.OPC,B(this,e,"f"),r,E.rs1.name),f.funct12=new _s(as.OPC,B(this,e,"f"),i,E.i_funct12.name),this.asmFrags.push(f.opcode),this.binFrags.push(f.funct12,f.rs1,f.funct3,f.rd,f.opcode);else{const s=i,t=gs(c),e=function(s){const t=parseInt(s,j.bin),i=Object.entries(N).find((s=>s[1]===t));return i?i[0]:"0x"+t.toString(16).padStart(3,"0")}(s);let n,o;"0"===m[0]?(n=gs(r),o=E.rs1.name):(n=Ms(r,!1),o=E.i_imm_4_0.name),f.rd=new _s(as.RD,t,c,E.rd.name),f.csr=new _s(as.CSR,e,s,E.i_csr.name),f.rs1=new _s(as.RS1,n,r,o),this.asmFrags.push(f.opcode,f.rd,f.csr,f.rs1),this.binFrags.push(f.csr,f.rs1,f.funct3,f.rd,f.opcode)}},u=function(){const s={imm_11_5:bs(i=B(this,t,"f"),E.s_imm_11_5.pos),rs2:bs(i,E.rs2.pos),rs1:bs(i,E.rs1.pos),funct3:bs(i,E.funct3.pos),imm_4_0:bs(i,E.s_imm_4_0.pos)};var i;const r=s.imm_11_5,m=s.rs2,c=s.rs1,o=s.funct3,f=s.imm_4_0,h=r+f,a=B(this,n,"f")===$.STORE_FP;if(A(this,e,a?ts[o]:G[o],"f"),void 0===B(this,e,"f"))throw`Detected STORE${a?"-FP":""} instruction but invalid funct3 field`;const d=Ms(h),_=gs(c),u=gs(m,a),p={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),o,E.funct3.name),rs1:new _s(as.RS1,_,c,E.rs1.name,!0),rs2:new _s(as.RS2,u,m,E.rs2.name),imm_4_0:new _s(as.IMM,d,f,E.s_imm_4_0.name),imm_11_5:new _s(as.IMM,d,r,E.s_imm_11_5.name),imm:new _s(as.IMM,d,h,"imm")};this.asmFrags.push(p.opcode,p.rs2,p.imm,p.rs1),this.binFrags.push(p.imm_11_5,p.rs2,p.rs1,p.funct3,p.imm_4_0,p.opcode)},p=function(){const s={imm_12:bs(i=B(this,t,"f"),E.b_imm_12.pos),imm_10_5:bs(i,E.b_imm_10_5.pos),rs2:bs(i,E.rs2.pos),rs1:bs(i,E.rs1.pos),funct3:bs(i,E.funct3.pos),imm_4_1:bs(i,E.b_imm_4_1.pos),imm_11:bs(i,E.b_imm_11.pos)};var i;const r=s.imm_12,m=s.imm_10_5,c=s.rs2,o=s.rs1,f=s.funct3,h=s.imm_4_1,a=s.imm_11,d=r+a+m+h+"0";if(A(this,e,K[f],"f"),void 0===B(this,e,"f"))throw"Detected BRANCH instruction but invalid funct3 field";const _=Ms(d),u=gs(c),p=gs(o),l={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),f,E.funct3.name),rs1:new _s(as.RS1,p,o,E.rs1.name),rs2:new _s(as.RS2,u,c,E.rs2.name),imm_12:new _s(as.IMM,_,r,E.b_imm_12.name),imm_11:new _s(as.IMM,_,a,E.b_imm_11.name),imm_10_5:new _s(as.IMM,_,m,E.b_imm_10_5.name),imm_4_1:new _s(as.IMM,_,h,E.b_imm_4_1.name),imm:new _s(as.IMM,_,d,"imm")};this.asmFrags.push(l.opcode,l.rs1,l.rs2,l.imm),this.binFrags.push(l.imm_12,l.imm_10_5,l.rs2,l.rs1,l.funct3,l.imm_4_1,l.imm_11,l.opcode)},l=function(){const s=bs(B(this,t,"f"),E.u_imm_31_12.pos),i=bs(B(this,t,"f"),E.rd.pos),r=Ms(s),m=gs(i);A(this,e,B(this,n,"f")===$.AUIPC?"auipc":"lui","f");const c={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.opcode.name),rd:new _s(as.RD,m,i,E.rd.name),imm_31_12:new _s(as.IMM,r,s,E.u_imm_31_12.name)};this.asmFrags.push(c.opcode,c.rd,c.imm_31_12),this.binFrags.push(c.imm_31_12,c.rd,c.opcode)},w=function(){const s=bs(B(this,t,"f"),E.j_imm_20.pos),i=bs(B(this,t,"f"),E.j_imm_10_1.pos),r=bs(B(this,t,"f"),E.j_imm_11.pos),m=bs(B(this,t,"f"),E.j_imm_19_12.pos),c=bs(B(this,t,"f"),E.rd.pos),o=s+m+r+i+"0";A(this,e,"jal","f");const f=Ms(o),h=gs(c),a={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.opcode.name),rd:new _s(as.RD,h,c,E.rd.name),imm_20:new _s(as.IMM,f,s,E.j_imm_20.name),imm_10_1:new _s(as.IMM,f,i,E.j_imm_10_1.name),imm_11:new _s(as.IMM,f,r,E.j_imm_11.name),imm_19_12:new _s(as.IMM,f,m,E.j_imm_19_12.name),imm:new _s(as.IMM,f,o,"imm")};this.asmFrags.push(a.opcode,a.rd,a.imm),this.binFrags.push(a.imm_20,a.imm_10_1,a.imm_11,a.imm_19_12,a.rd,a.opcode)},b=function(){const s=ps(B(this,t,"f")),i=s.funct5,r=s.aq,m=s.rl,c=s.rs2,o=s.rs1,f=s.funct3,h=s.rd;if(A(this,e,Z[i+f],"f"),void 0===B(this,e,"f"))throw"Detected AMO instruction but invalid funct5 and funct3 fields";const a=/^lr\./.test(B(this,e,"f")),d=gs(h),_=gs(o),u=a?"n/a":gs(c),p={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.opcode.name),rd:new _s(as.RD,d,h,E.rd.name),funct3:new _s(as.OPC,B(this,e,"f"),f,E.funct3.name),rs1:new _s(as.RS1,_,o,E.rs1.name,!0),rs2:new _s(as.OPC,u,c,E.rs2.name),rl:new _s(as.OPC,B(this,e,"f"),m,E.r_rl.name),aq:new _s(as.OPC,B(this,e,"f"),r,E.r_aq.name),funct5:new _s(as.OPC,B(this,e,"f"),i,E.r_funct5.name)};this.asmFrags.push(p.opcode,p.rd),a||(p.rs2.id=as.RS2,this.asmFrags.push(p.rs2)),this.asmFrags.push(p.rs1),this.binFrags.push(p.funct5,p.aq,p.rl,p.rs2,p.rs1,p.funct3,p.rd,p.opcode)},M=function(){const s=ps(B(this,t,"f")),i=s.funct5,r=s.fmt,m=s.rs2,c=s.rs1,o=s.funct3,f=s.rd;switch(B(this,n,"f")){case $.MADD:A(this,e,es[r],"f");break;case $.MSUB:A(this,e,ns[r],"f");break;case $.NMADD:A(this,e,rs[r],"f");break;case $.NMSUB:A(this,e,ms[r],"f")}if(void 0===B(this,e,"f"))throw"Detected fused multiply-add instruction but invalid fmt field";const h=gs(c,!0),a=gs(m,!0),d=gs(i,!0),_=gs(f,!0),u={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.opcode.name),fmt:new _s(as.OPC,B(this,e,"f"),r,E.r_fp_fmt.name),rm:new _s(as.OPC,B(this,e,"f"),o,"rm"),rd:new _s(as.RD,_,f,E.rd.name),rs1:new _s(as.RS1,h,c,E.rs1.name),rs2:new _s(as.RS2,a,m,E.rs2.name),rs3:new _s(as.RS3,d,i,"rs3")};this.asmFrags.push(u.opcode,u.rd,u.rs1,u.rs2,u.rs3),this.binFrags.push(u.rs3,u.fmt,u.rs2,u.rs1,u.rm,u.rd,u.opcode)},v=function(){var s;const i=ws(B(this,t,"f"));return A(this,e,cs[i.funct3],"f"),"object"==typeof B(this,e,"f")&&A(this,e,null!==(s=B(this,e,"f")[B(this,r,"f")])&&void 0!==s?s:B(this,e,"f")[V.all],"f"),hs[B(this,e,"f")]},g=function(){var s,i;const n=ws(B(this,t,"f"));if(A(this,e,os[n.funct3],"f"),"object"==typeof B(this,e,"f")&&(A(this,e,null!==(s=B(this,e,"f")[B(this,r,"f")])&&void 0!==s?s:B(this,e,"f")[V.all],"f"),"object"==typeof B(this,e,"f"))){const s=Ms(n.rd_rs1,!1);A(this,e,null!==(i=B(this,e,"f")[s])&&void 0!==i?i:B(this,e,"f").default,"f"),"object"==typeof B(this,e,"f")&&(A(this,e,B(this,e,"f")[n.funct2_cb],"f"),"object"==typeof B(this,e,"f")&&A(this,e,B(this,e,"f")[n.funct6[3]+n.funct2],"f"))}return hs[B(this,e,"f")]},P=function(){var s,i,n;const m=ws(B(this,t,"f"));if(A(this,e,fs[m.funct3],"f"),"object"==typeof B(this,e,"f")&&(A(this,e,null!==(s=B(this,e,"f")[B(this,r,"f")])&&void 0!==s?s:B(this,e,"f")[V.all],"f"),"object"==typeof B(this,e,"f")&&(A(this,e,B(this,e,"f")[m.funct4[3]],"f"),"object"==typeof B(this,e,"f")))){const s=Ms(m.rs2,!1);if(A(this,e,null!==(i=B(this,e,"f")[s])&&void 0!==i?i:B(this,e,"f").default,"f"),"object"==typeof B(this,e,"f")){const s=Ms(m.rd_rs1,!1);A(this,e,null!==(n=B(this,e,"f")[s])&&void 0!==n?n:B(this,e,"f").default,"f")}}return hs[B(this,e,"f")]},O=function(s){var i,r;const m=bs(B(this,t,"f"),E.c_funct4.pos),c=bs(B(this,t,"f"),E.c_rd_rs1.pos),o=bs(B(this,t,"f"),E.c_rs2.pos),f=(bs(B(this,t,"f"),E.c_opcode.pos),gs(c)),h=gs(o),a=Ms(c,!1);if(null===(i=s.rdRs1Excl)||void 0===i?void 0:i.includes(a))throw`Detected ${B(this,e,"f")} instruction, but illegal value "${f}" in rd/rs1 field`;const d=Ms(o,!1);if(null===(r=s.rs2Excl)||void 0===r?void 0:r.includes(d))throw`Detected ${B(this,e,"f")} instruction, but illegal value "${h}" in rs2 field`;let _;switch(s.rdRs1Mask){case 1:_=E.c_rs1.name;break;case 2:_=E.c_rd.name;break;default:_=E.c_rd_rs1.name}void 0!==s.rdRs1Excl&&(_+="≠"+Cs(s.rdRs1Excl));let u=E.c_rs2.name;void 0!==s.rs2Excl&&(u+="≠"+Cs(s.rs2Excl));const p={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.c_opcode.name),funct4:new _s(as.OPC,B(this,e,"f"),m,E.c_funct4.name)},l=void 0===s.rdRs1Val;p.rd_rs1=l?new _s(as.RD,f,c,_):new _s(as.OPC,B(this,e,"f"),c,"static-"+_);const w=void 0===s.rs2Val;p.rs2=w?new _s(as.RS2,h,o,u):new _s(as.OPC,B(this,e,"f"),o,"static-"+u),this.asmFrags.push(p.opcode),l&&(this.asmFrags.push(p.rd_rs1),w&&this.asmFrags.push(p.rs2)),this.binFrags.push(p.funct4,p.rd_rs1,p.rs2,p.opcode)},C=function(s){var i,r;const m=bs(B(this,t,"f"),E.c_funct3.pos),c=bs(B(this,t,"f"),E.c_imm_ci_0.pos),o=bs(B(this,t,"f"),E.c_rd_rs1.pos),f=bs(B(this,t,"f"),E.c_imm_ci_1.pos),h=(bs(B(this,t,"f"),E.c_opcode.pos),/^c\.slli/.test(B(this,e,"f"))),a=gs(o,/^c\.fl/.test(B(this,e,"f"))),d=vs([c,f],s.immBits,s.uimm);if(h)if(0===d){if(A(this,e,B(this,e,"f")+"64","f"),void 0===(s=hs[B(this,e,"f")]))throw`Internal error when converting shift-immediate instruction into ${B(this,e,"f")}`;this.isa="RV128"+s.isa}else"1"===c&&/^RV32/.test(this.isa)&&(this.isa="RV64"+s.isa);const _=Ms(o,!1);if(null===(i=s.rdRs1Excl)||void 0===i?void 0:i.includes(_))throw`Detected ${B(this,e,"f")} instruction, but illegal value "${a}" in rd/rs1 field`;if(s.nzimm&&0===d)throw`Detected ${B(this,e,"f")}, but instruction expects non-zero immediate value (encoding reserved)`;let u;switch(s.rdRs1Mask){case 1:u=E.c_rs1.name;break;case 2:u=E.c_rd.name;break;default:u=E.c_rd_rs1.name}void 0!==s.rdRs1Excl&&(u+="≠"+Cs(s.rdRs1Excl));let p="";h||(s.nzimm&&(p+="nz"),s.uimm&&(p+="u")),p+=h?E.c_shamt_0.name:E.c_imm_ci_0.name;const l={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.c_opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),m,E.c_funct3.name)},w=void 0===s.rdRs1Val;l.rd_rs1=w?new _s(as.RD,a,o,u):new _s(as.OPC,B(this,e,"f"),o,"static-"+u);const b=null!==(r=s.immBitsLabels)&&void 0!==r?r:s.immBits,M=void 0===s.immVal;M?(l.imm0=new _s(as.IMM,d,c,p+Os(b[0])),l.imm1=new _s(as.IMM,d,f,p+Os(b[1]))):(l.imm0=new _s(as.OPC,B(this,e,"f"),c,"static-"+p+Os(b[0])),l.imm1=new _s(as.OPC,B(this,e,"f"),f,"static-"+p+Os(b[1]))),this.asmFrags.push(l.opcode),w&&this.asmFrags.push(l.rd_rs1),M&&this.asmFrags.push(l.imm0),this.binFrags.push(l.funct3,l.imm0,l.rd_rs1,l.imm1,l.opcode)},R=function(s){const i=bs(B(this,t,"f"),E.c_funct3.pos),r=bs(B(this,t,"f"),E.c_imm_css.pos),m=bs(B(this,t,"f"),E.c_rs2.pos);let c="";s.uimm&&(c+="u"),c+=E.c_imm_css.name;const o=/^c\.f/.test(B(this,e,"f")),f=vs(r,s.immBits,s.uimm),h=gs(m,o),a={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.c_opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),i,E.c_funct3.name),rs2:new _s(as.RS2,h,m,E.c_rs2.name),imm:new _s(as.IMM,f,r,c+Os(s.immBits))};this.asmFrags.push(a.opcode,a.rs2,a.imm),this.binFrags.push(a.funct3,a.imm,a.rs2,a.opcode)},I=function(s){const i=bs(B(this,t,"f"),E.c_funct3.pos),r=bs(B(this,t,"f"),E.c_imm_ciw.pos),m=bs(B(this,t,"f"),E.c_rd_prime.pos);bs(B(this,t,"f"),E.c_opcode.pos);let c="";s.nzimm&&(c+="nz"),s.uimm&&(c+="u"),c+=E.c_imm_ciw.name;const o=gs("01"+m),f=vs(r,s.immBits,s.uimm);if(s.nzimm&&0===f)throw`Detected ${B(this,e,"f")}, but instruction expects non-zero immediate value (encoding reserved)`;const h={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.c_opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),i,E.c_funct3.name),rd_prime:new _s(as.RD,o,m,E.c_rd_prime.name),imm:new _s(as.IMM,f,r,c+Os(s.immBits))};this.asmFrags.push(h.opcode,h.rd_prime,h.imm),this.binFrags.push(h.funct3,h.imm,h.rd_prime,h.opcode)},F=function(s){const i=bs(B(this,t,"f"),E.c_funct3.pos),r=bs(B(this,t,"f"),E.c_imm_cl_0.pos),m=bs(B(this,t,"f"),E.c_rs1_prime.pos),c=bs(B(this,t,"f"),E.c_imm_cl_1.pos),o=bs(B(this,t,"f"),E.c_rd_prime.pos);bs(B(this,t,"f"),E.c_opcode.pos);let f="";s.uimm&&(f+="u"),f+=E.c_imm_cl_0.name;const h="01"+m,a=gs("01"+o,/^c\.f/.test(B(this,e,"f"))),d=vs([r,c],s.immBits,s.uimm),_=gs(h),u={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.c_opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),i,E.c_funct3.name),rd_prime:new _s(as.RD,a,o,E.c_rd_prime.name),rs1_prime:new _s(as.RS1,_,m,E.c_rs1_prime.name,!0),imm0:new _s(as.IMM,d,r,f+Os(s.immBits[0])),imm1:new _s(as.IMM,d,c,f+Os(s.immBits[1]))};this.asmFrags.push(u.opcode,u.rd_prime,u.imm0,u.rs1_prime),this.binFrags.push(u.funct3,u.imm0,u.rs1_prime,u.imm1,u.rd_prime,u.opcode)},S=function(s){const i=bs(B(this,t,"f"),E.c_funct3.pos),r=bs(B(this,t,"f"),E.c_imm_cl_0.pos),m=bs(B(this,t,"f"),E.c_rs1_prime.pos),c=bs(B(this,t,"f"),E.c_imm_cl_1.pos),o=bs(B(this,t,"f"),E.c_rs2_prime.pos);bs(B(this,t,"f"),E.c_opcode.pos);let f="";s.uimm&&(f+="u"),f+=E.c_imm_cs_0.name;const h="01"+m,a=gs("01"+o,/^c\.f/.test(B(this,e,"f"))),d=vs([r,c],s.immBits,s.uimm),_=gs(h),u={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.c_opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),i,E.c_funct3.name),rs2_prime:new _s(as.RS2,a,o,E.c_rs2_prime.name),rs1_prime:new _s(as.RS1,_,m,E.c_rs1_prime.name,!0),imm0:new _s(as.IMM,d,r,f+Os(s.immBits[0])),imm1:new _s(as.IMM,d,c,f+Os(s.immBits[1]))};this.asmFrags.push(u.opcode,u.rs2_prime,u.imm0,u.rs1_prime),this.binFrags.push(u.funct3,u.imm0,u.rs1_prime,u.imm1,u.rs2_prime,u.opcode)},D=function(){const s=bs(B(this,t,"f"),E.c_funct6.pos),i=bs(B(this,t,"f"),E.c_rd_rs1_prime.pos),r=bs(B(this,t,"f"),E.c_funct2.pos),m=bs(B(this,t,"f"),E.c_rs2_prime.pos),c=(bs(B(this,t,"f"),E.c_opcode.pos),"01"+m),o=gs("01"+i),f=gs(c),h={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.c_opcode.name),funct6:new _s(as.OPC,B(this,e,"f"),s,E.c_funct6.name),funct2:new _s(as.OPC,B(this,e,"f"),r,E.c_funct2.name),rd_rs1_prime:new _s(as.RD,o,i,E.c_rs2_prime.name),rs2_prime:new _s(as.RS2,f,m,E.c_rs1_prime.name)};this.asmFrags.push(h.opcode,h.rd_rs1_prime,h.rs2_prime),this.binFrags.push(h.funct6,h.rd_rs1_prime,h.funct2,h.rs2_prime,h.opcode)},k=function(s){const i=bs(B(this,t,"f"),E.c_funct3.pos),r=bs(B(this,t,"f"),E.c_imm_cb_0.pos),m=bs(B(this,t,"f"),E.c_shamt_0.pos),c=bs(B(this,t,"f"),E.c_funct2_cb.pos),o=bs(B(this,t,"f"),E.c_rd_rs1_prime.pos),f=bs(B(this,t,"f"),E.c_imm_cb_1.pos),h=bs(B(this,t,"f"),E.c_shamt_1.pos),a=(bs(B(this,t,"f"),E.c_opcode.pos),/^c\.b/.test(B(this,e,"f"))),d=/^c\.sr[la]i/.test(B(this,e,"f")),_=gs("01"+o),u=vs([r,f],s.immBits,s.uimm);if(d)if(0===u){if(A(this,e,B(this,e,"f")+"64","f"),void 0===(s=hs[B(this,e,"f")]))throw`Internal error when converting shift-immediate instruction into ${B(this,e,"f")}`;this.isa="RV128"+s.isa}else"1"===m&&/^RV32/.test(this.isa)&&(this.isa="RV64"+s.isa);if(s.nzimm&&0===u)throw`Detected ${B(this,e,"f")}, but instruction expects non-zero immediate value (encoding reserved)`;let p="";d||(s.nzimm&&(p+="nz"),s.uimm&&(p+="u")),p+=d?E.c_shamt_0.name:a?E.c_imm_cb_0.name:E.c_imm_ci_0.name;const l={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.c_opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),i,E.c_funct3.name),funct2:new _s(as.OPC,B(this,e,"f"),c,E.c_funct2.name),rd_rs1_prime:new _s(as.RD,_,o,E.c_rs2_prime.name)};if(a)l.imm0=new _s(as.IMM,u,r,p+Os(s.immBits[0])),l.imm1=new _s(as.IMM,u,f,p+Os(s.immBits[1])),this.asmFrags.push(l.opcode,l.rd_rs1_prime,l.imm0),this.binFrags.push(l.funct3,l.imm0,l.rd_rs1_prime,l.imm1,l.opcode);else{const t=void 0===s.immVal;t?(l.imm0=new _s(as.IMM,u,m,p+Os(s.immBits[0])),l.imm1=new _s(as.IMM,u,h,p+Os(s.immBits[1]))):(l.imm0=new _s(as.OPC,B(this,e,"f"),m,"static-"+p+Os(s.immBits[0])),l.imm1=new _s(as.OPC,B(this,e,"f"),h,"static-"+p+Os(s.immBits[1]))),this.asmFrags.push(l.opcode,l.rd_rs1_prime),t&&this.asmFrags.push(l.imm0),this.binFrags.push(l.funct3,l.imm0,l.funct2,l.rd_rs1_prime,l.imm1,l.opcode)}},y=function(s){const i=bs(B(this,t,"f"),E.c_funct3.pos),r=bs(B(this,t,"f"),E.c_imm_cj.pos),m=(bs(B(this,t,"f"),E.c_opcode.pos),vs(r,s.immBits)),c={opcode:new _s(as.OPC,B(this,e,"f"),B(this,n,"f"),E.c_opcode.name),funct3:new _s(as.OPC,B(this,e,"f"),i,E.c_funct3.name),imm:new _s(as.IMM,m,r,E.c_imm_cj.name+Os(s.immBits))};this.asmFrags.push(c.opcode,c.imm),this.binFrags.push(c.funct3,c.imm,c.opcode)};export function decRegAbi(s,t=!1){return Object.keys(t?T:z)[parseInt(s,j.dec)]}function Ps(s){let t="";const i=["i","o","r","w"];for(let e=0;e<s.length;e++)"1"===s[e]&&(t+=i[e]);if(""===t)throw"Invalid IO/Mem field";return t}function Os(s){let t="[",i=!1;for(const e of s)i?t+="|":i=!0,t+=e instanceof Array?e[0]+":"+e[1]:e;return t+"]"}function Cs(s){if(1===s.length)return s[0].toString();let t="{",i=!1;for(const e of s)i?t+=",":i=!0,t+=e;return t+"}"}
✄
export class Encoder {
    /**
     * Creates an Encoder to convert an assembly instruction to binary
     * @param {String} asm
     */
    constructor(asm: string, config: any);
    /**
     * Binary representation of instruction
     * @type String
     */
    bin: string;
    /**
     * Value from XLEN_MASK for passing the expected xlen to the decoder
     * - Only matters for C instructions,
     *   set to `XLEN_MASK.all` for all standard 32-bit instructions
     * @type Integer
     */
    xlens: Integer;
    #private;
}

✄
var t,i,s,e,f,n,h,o,c,r,a,l,m,u,d,p,b,v,_,w,I,g,$,x,k,S,R,M,N=this&&this.__classPrivateFieldSet||function(t,i,s,e,f){if("m"===e)throw new TypeError("Private method is not writable");if("a"===e&&!f)throw new TypeError("Private accessor was defined without a setter");if("function"==typeof i?t!==i||!f:!i.has(t))throw new TypeError("Cannot write private member to an object whose class did not declare it");return"a"===e?f.call(t,s):f?f.value=s:i.set(t,s),s},P=this&&this.__classPrivateFieldGet||function(t,i,s,e){if("a"===s&&!e)throw new TypeError("Private accessor was defined without a getter");if("function"==typeof i?t!==i||!e:!i.has(t))throw new TypeError("Cannot read private member from an object whose class did not declare it");return"m"===s?e:"a"===s?e.call(t):e?e.value:i.get(t)};import{BASE as V,XLEN_MASK as A,FIELDS as C,OPCODE as B,ISA as O,REGISTER as E,FLOAT_REGISTER as y,CSR as D}from"./Constants.js";import{COPTS_ISA as T}from"./Config.js";import{convertBase as j}from"./Instruction.js";export class Encoder{constructor(h,o){t.add(this),i.set(this,void 0),s.set(this,void 0),e.set(this,void 0),f.set(this,void 0),N(this,i,o,"f");const c=h.toLowerCase().split(/[ ,()]+/);P(this,t,"m",n).call(this,c)}}function L(t,i){return(Number(t)>>>0).toString(V.bin).padStart(i,"0").slice(-i)}function F(t,i){let s=L(t,18),e="";for(let t of i)e+="number"==typeof t?s[17-t]:s.substring(17-t[0],18-t[1]);return e}function U(t){return Number("0b1"+"".padStart(function t(i){let s=1/0;if("number"==typeof i)return i;for(let e of i)s=Math.min(s,t(e));return s}(t),"0"))}function z(t,i=!1){var s;let e=i?"f":"x";if(void 0===(t=null!==(s=i?y[t]:E[t])&&void 0!==s?s:t)||0===t.length)return"00000";if(t[0]!==e||!/^[fx]\d+/.test(t))throw`Invalid or unknown ${i?"float ":""}register format: "${t}"`;let f=parseInt(t.substring(1));if(isNaN(f))f=0;else if(f<0||f>31)throw`Register address out of range: "${t}"`;return j(f,V.dec,V.bin,5)}function W(t,i=!1){if(void 0===t)return"000";const s=z(t,i);if("01"!==s.substring(0,2)){const s=i?"f":"x";throw`Invalid register "${t}", rd' field expects compressable register from ${s}8 to ${s}15`}return s.substring(2)}function J(t){let i="";const s=["i","o","r","w"];let e=0;for(let f=0;f<s.length;f++)t.includes(s[f])?(i+="1",e++):i+="0";if(e!==t.length||"0000"===i)throw`Invalid IO/Mem field '${t}', expected some combination of 'iorw'`;return i}i=new WeakMap,s=new WeakMap,e=new WeakMap,f=new WeakMap,t=new WeakSet,n=function(n){var V,C;if(N(this,e,n[0],"f"),N(this,f,n.splice(1),"f"),N(this,s,O[P(this,e,"f")],"f"),void 0===P(this,s,"f"))throw"Invalid mnemonic: "+P(this,e,"f");const E=2===P(this,s,"f").opcode.length;let y=P(this,s,"f").isa;if(this.xlens=0,E)this.xlens=P(this,s,"f").xlens,0!=(this.xlens&A.rv32)?y=`RV32${y}`:0!=(this.xlens&A.rv64)?y=`RV64${y}`:0!=(this.xlens&A.rv128)&&(y=`RV128${y}`);else{switch(parseInt(null===(V=/^RV(\d+)/.exec(P(this,s,"f").isa))||void 0===V?void 0:V[1])){case 32:this.xlens|=A.rv32;case 64:this.xlens|=A.rv64;case 128:this.xlens|=A.rv128;break;default:this.xlens=A.all}}if(P(this,i,"f").ISA!==T.AUTO){if(P(this,i,"f").ISA===T.RV32I&&0==(this.xlens&A.rv32))throw`Detected ${y} instruction incompatible with configuration ISA: RV32I`;if(P(this,i,"f").ISA===T.RV64I&&0==(this.xlens&A.rv64))throw`Detected ${y} instruction incompatible with configuration ISA: RV64I`;if(P(this,i,"f").ISA===T.RV128I&&0==(this.xlens&A.rv128))throw`Detected ${y} instruction incompatible with configuration ISA: RV128I`}if(E){switch(null===(C=/^([^-]+)-/.exec(P(this,s,"f").fmt))||void 0===C?void 0:C[1]){case"CR":P(this,t,"m",w).call(this);break;case"CI":P(this,t,"m",I).call(this);break;case"CSS":P(this,t,"m",g).call(this);break;case"CIW":P(this,t,"m",$).call(this);break;case"CL":P(this,t,"m",x).call(this);break;case"CS":P(this,t,"m",k).call(this);break;case"CA":P(this,t,"m",S).call(this);break;case"CB":P(this,t,"m",R).call(this);break;case"CJ":P(this,t,"m",M).call(this);break;default:throw`Unsupported C instruction format: ${P(this,s,"f").fmt}`}}else switch(P(this,s,"f").opcode){case B.OP:case B.OP_32:case B.OP_64:P(this,t,"m",h).call(this);break;case B.OP_FP:P(this,t,"m",o).call(this);break;case B.AMO:P(this,t,"m",v).call(this);break;case B.JALR:P(this,t,"m",c).call(this);break;case B.LOAD:case B.LOAD_FP:P(this,t,"m",r).call(this);break;case B.OP_IMM:case B.OP_IMM_32:case B.OP_IMM_64:P(this,t,"m",a).call(this);break;case B.MISC_MEM:P(this,t,"m",l).call(this);break;case B.SYSTEM:P(this,t,"m",m).call(this);break;case B.STORE:case B.STORE_FP:P(this,t,"m",u).call(this);break;case B.BRANCH:P(this,t,"m",d).call(this);break;case B.LUI:case B.AUIPC:P(this,t,"m",p).call(this);break;case B.JAL:P(this,t,"m",b).call(this);break;case B.MADD:case B.MSUB:case B.NMADD:case B.NMSUB:P(this,t,"m",_).call(this);break;default:throw"Unsupported opcode: "+P(this,s,"f").opcode}},h=function(){const t=P(this,f,"f")[0],i=P(this,f,"f")[1],e=P(this,f,"f")[2],n=z(t),h=z(i),o=z(e);this.bin=P(this,s,"f").funct7+o+h+P(this,s,"f").funct3+n+P(this,s,"f").opcode},o=function(){var t,i;const e=P(this,f,"f")[0],n=P(this,f,"f")[1],h=P(this,f,"f")[2];let o=!0,c=!0;"1"===P(this,s,"f").funct5[0]&&("1"===P(this,s,"f").funct5[3]?c=!1:o=!1);const r=z(e,o),a=z(n,c),l=null!==(t=P(this,s,"f").rs2)&&void 0!==t?t:z(h,!0),m=null!==(i=P(this,s,"f").funct3)&&void 0!==i?i:"111";this.bin=P(this,s,"f").funct5+P(this,s,"f").fp_fmt+l+a+m+r+P(this,s,"f").opcode},c=function(){const t=P(this,f,"f")[0],i=P(this,f,"f")[1],e=P(this,f,"f")[2],n=z(t),h=z(i),o=L(e,C.i_imm_11_0.pos[1]);this.bin=o+h+P(this,s,"f").funct3+n+P(this,s,"f").opcode},r=function(){const t=P(this,f,"f")[0],i=P(this,f,"f")[1],e=P(this,f,"f")[2],n=z(t,P(this,s,"f").opcode===B.LOAD_FP),h=z(e),o=L(i,C.i_imm_11_0.pos[1]);this.bin=o+h+P(this,s,"f").funct3+n+P(this,s,"f").opcode},a=function(){const t=P(this,f,"f")[0],n=P(this,f,"f")[1],h=P(this,f,"f")[2],o=z(t),c=z(n);let r="".padStart("0",C.i_imm_11_0.pos[1]);if(/^s[lr][al]i/.test(P(this,e,"f"))){let t;if(t=P(this,i,"f").isa===T.RV32I||P(this,s,"f").opcode===B.OP_IMM_32?C.i_shamt.pos[1]:P(this,i,"f").isa===T.RV64I||P(this,s,"f").opcode===B.OP_IMM_64?C.i_shamt_5_0.pos[1]:C.i_shamt_6_0.pos[1],h<0||h>=1<<t)throw'Invalid shamt field (out of range): "'+h+'"';r="0"+P(this,s,"f").shtyp+"000"+L(h,C.i_shamt_6_0.pos[1])}else r=L(h,C.i_imm_11_0.pos[1]);this.bin=r+c+P(this,s,"f").funct3+o+P(this,s,"f").opcode},l=function(){let t="".padStart(C.rs1.pos[1],"0"),i="".padStart(C.rd.pos[1],"0"),n="".padStart(C.i_imm_11_0.pos[1],"0");if("lq"===P(this,e,"f")){const s=P(this,f,"f")[0],e=P(this,f,"f")[1],h=P(this,f,"f")[2];i=z(s),n=L(e,C.i_imm_11_0.pos[1]),t=z(h)}else if("fence"===P(this,e,"f")){const t=P(this,f,"f")[0],i=P(this,f,"f")[1];n="0000"+J(t)+J(i)}this.bin=n+t+P(this,s,"f").funct3+i+P(this,s,"f").opcode},m=function(){let t,i,e;if("Zicsr"==P(this,s,"f").isa){const n=P(this,f,"f")[0],h=P(this,f,"f")[1],o=P(this,f,"f")[2];i=z(n),e=function(t){let i=D[t];if(void 0===i&&(i=Number(t)>>>0,0===i&&0!=t))throw`Invalid or unknown CSR name: "${t}"`;return L(i,C.i_csr.pos[1])}(h),t="0"===P(this,s,"f").funct3[0]?z(o):L(o,C.rs1.pos[1])}else t="".padStart(C.rs1.pos[1],"0"),i="".padStart(C.rd.pos[1],"0"),e=P(this,s,"f").funct12;this.bin=e+t+P(this,s,"f").funct3+i+P(this,s,"f").opcode},u=function(){const t=P(this,f,"f")[0],i=P(this,f,"f")[1],e=P(this,f,"f")[2],n=C.s_imm_11_5.pos[1],h=C.s_imm_4_0.pos[1],o=z(t,P(this,s,"f").opcode===B.STORE_FP),c=z(e),r=L(i,n+h),a=r.substring(0,n),l=r.substring(n,n+h);this.bin=a+o+c+P(this,s,"f").funct3+l+P(this,s,"f").opcode},d=function(){const t=P(this,f,"f")[0],i=P(this,f,"f")[1],e=P(this,f,"f")[2],n=C.b_imm_12.pos[1],h=C.b_imm_11.pos[1],o=C.b_imm_10_5.pos[1],c=C.b_imm_4_1.pos[1],r=z(t),a=z(i),l=L(e,n+h+o+c+1),m=l.substring(0,n),u=l.substring(n,n+h),d=l.substring(n+h,n+h+o),p=l.substring(n+h+o,n+h+o+c);this.bin=m+d+a+r+P(this,s,"f").funct3+p+u+P(this,s,"f").opcode},p=function(){const t=P(this,f,"f")[0],i=P(this,f,"f")[1],e=z(t),n=L(i,C.u_imm_31_12.pos[1]);this.bin=n+e+P(this,s,"f").opcode},b=function(){const t=P(this,f,"f")[0],i=P(this,f,"f")[1],e=C.j_imm_20.pos[1],n=C.j_imm_10_1.pos[1],h=C.j_imm_11.pos[1],o=C.j_imm_19_12.pos[1],c=z(t),r=L(i,e+o+h+n+1),a=r.substring(0,e),l=r.substring(e,e+o),m=r.substring(e+o,e+o+h),u=r.substring(e+o+h,e+o+h+n);this.bin=a+u+m+l+c+P(this,s,"f").opcode},v=function(){let t,i,n;/^lr\./.test(P(this,e,"f"))?(t=P(this,f,"f")[0],i=P(this,f,"f")[1],n="x0"):(t=P(this,f,"f")[0],i=P(this,f,"f")[2],n=P(this,f,"f")[1]);const h=z(t),o=z(i),c=z(n);this.bin=P(this,s,"f").funct5+"00"+c+o+P(this,s,"f").funct3+h+P(this,s,"f").opcode},_=function(){const t=P(this,f,"f")[0],i=P(this,f,"f")[1],e=P(this,f,"f")[2],n=P(this,f,"f")[3],h=z(t,!0),o=z(i,!0),c=z(e,!0),r=z(n,!0),a=P(this,s,"f").fp_fmt;this.bin=r+a+c+o+"111"+h+P(this,s,"f").opcode},w=function(){const t=P(this,f,"f")[0],i=P(this,f,"f")[1],n=void 0!==P(this,s,"f").rdRs1Val?L(P(this,s,"f").rdRs1Val,C.c_rd_rs1.pos[1]):void 0===t?"01000":z(t),h=void 0!==P(this,s,"f").rs2Val?L(P(this,s,"f").rs2Val,C.c_rs2.pos[1]):void 0===i?"01000":z(i);if(void 0!==P(this,s,"f").rdRs1Excl){const i=parseInt(n,V.bin);for(const f of P(this,s,"f").rdRs1Excl)if(i===f)throw`Illegal value "${t}" in rd/rs1 field for instruction ${P(this,e,"f")}`}if(void 0!==P(this,s,"f").rs2Excl){const t=parseInt(h,V.bin);for(const f of P(this,s,"f").rs2Excl)if(t===f)throw`Illegal value "${i}" in rs2 field for instruction ${P(this,e,"f")}`}this.bin=P(this,s,"f").funct4+n+h+P(this,s,"f").opcode},I=function(){var t;const i=void 0!==P(this,s,"f").rdRs1Val,n=P(this,f,"f")[0],h=P(this,f,"f")[i?0:1],o=/^c\.f/.test(P(this,e,"f")),c=i?L(P(this,s,"f").rdRs1Val,C.c_rd_rs1.pos[1]):void 0===n?"01000":z(n,o);let r=null!==(t=P(this,s,"f").immVal)&&void 0!==t?t:Number(h);if(void 0!==P(this,s,"f").rdRs1Excl){const t=parseInt(c,V.bin);for(const i of P(this,s,"f").rdRs1Excl)if(t===i)throw`Illegal value "${n}" in rd/rs1 field for instruction ${P(this,e,"f")}`}if(P(this,s,"f").nzimm&&(0===r||isNaN(r))){if(void 0!==h)throw`Invalid immediate "${h}", ${P(this,e,"f")} instruction expects non-zero value`;r=U(P(this,s,"f").immBits)}if(P(this,s,"f").uimm&&r<0)throw`Invalid immediate "${h}", ${P(this,e,"f")} instruction expects non-negative value`;const a=F(r,P(this,s,"f").immBits[0]),l=F(r,P(this,s,"f").immBits[1]);this.bin=P(this,s,"f").funct3+a+c+l+P(this,s,"f").opcode},g=function(){const t=P(this,f,"f")[0],i=P(this,f,"f")[1],n=z(t,/^c\.f/.test(P(this,e,"f")));let h=Number(i);if(P(this,s,"f").uimm&&h<0)throw`Invalid immediate "${i}", ${P(this,e,"f")} instruction expects non-negative value`;const o=F(h,P(this,s,"f").immBits);this.bin=P(this,s,"f").funct3+o+n+P(this,s,"f").opcode},$=function(){const t=P(this,f,"f")[0],i=P(this,f,"f")[1],n=W(t);let h=Number(i);if(P(this,s,"f").nzimm&&(0===h||isNaN(h))){if(void 0!==i)throw`Invalid immediate "${i}", ${P(this,e,"f")} instruction expects non-zero value`;h=U(P(this,s,"f").immBits)}if(P(this,s,"f").uimm&&h<0)throw`Invalid immediate "${i}", ${P(this,e,"f")} instruction expects non-negative value`;const o=F(h,P(this,s,"f").immBits);this.bin=P(this,s,"f").funct3+o+n+P(this,s,"f").opcode},x=function(){const t=P(this,f,"f")[0],i=P(this,f,"f")[1],n=P(this,f,"f")[2],h=W(t,/^c\.f/.test(P(this,e,"f"))),o=W(n);let c=Number(i);if(P(this,s,"f").uimm&&c<0)throw`Invalid immediate "${i}", ${P(this,e,"f")} instruction expects non-negative value`;const r=F(c,P(this,s,"f").immBits[0]),a=F(c,P(this,s,"f").immBits[1]);this.bin=P(this,s,"f").funct3+r+o+a+h+P(this,s,"f").opcode},k=function(){const t=P(this,f,"f")[0],i=P(this,f,"f")[1],n=P(this,f,"f")[2],h=W(t,/^c\.f/.test(P(this,e,"f"))),o=W(n);let c=Number(i);if(P(this,s,"f").uimm&&c<0)throw`Invalid immediate "${i}", ${P(this,e,"f")} instruction expects non-negative value`;const r=F(c,P(this,s,"f").immBits[0]),a=F(c,P(this,s,"f").immBits[1]);this.bin=P(this,s,"f").funct3+r+o+a+h+P(this,s,"f").opcode},S=function(){const t=P(this,f,"f")[0],i=P(this,f,"f")[1],e=W(t),n=W(i);this.bin=P(this,s,"f").funct6+e+P(this,s,"f").funct2+n+P(this,s,"f").opcode},R=function(){var t,i;const n=P(this,f,"f")[0],h=P(this,f,"f")[1],o=W(n);let c=null!==(t=P(this,s,"f").immVal)&&void 0!==t?t:Number(h);if(P(this,s,"f").nzimm&&(0===c||isNaN(c))){if(void 0!==h)throw`Invalid immediate "${h}", ${P(this,e,"f")} instruction expects non-zero value`;c=U(P(this,s,"f").immBits)}if(P(this,s,"f").uimm&&c<0)throw`Invalid immediate "${h}", ${P(this,e,"f")} instruction expects non-negative value`;const r=F(c,P(this,s,"f").immBits[0]),a=F(c,P(this,s,"f").immBits[1]),l=null!==(i=P(this,s,"f").funct2)&&void 0!==i?i:"";this.bin=P(this,s,"f").funct3+r+l+o+a+P(this,s,"f").opcode},M=function(){const t=F(P(this,f,"f")[0],P(this,s,"f").immBits);this.bin=P(this,s,"f").funct3+t+P(this,s,"f").opcode};
✄
export function convertBase(val: any, baseSrc: any, baseDst: any, Pad: any): string;
export function convertRegToAbi(reg: any): any;
/**
 * Represents an instruction
 * @class
 */
export class Instruction {
    /**
     * Creates an instruction represented in multiple formats
     * @param {String} instruction
     * @param {Object} configuration
     */
    constructor(instruction: string, config?: {});
    /**
     * ISA of instruction: 'RV32I', 'RV64I', 'EXT_M', 'EXT_A', etc.
     * @type String
     */
    isa: string;
    /**
     * Format of instruction: 'R-type', 'I-type', etc.
     * @type String
     */
    fmt: string;
    /**
     * Length of instruction: 16 or 32 bits
     * @type Number
     */
    len: number;
    /**
     * Assembly representation of instruction
     * @type String
     */
    asm: string;
    /**
     * Binary representation of instruction
     * @type String
     */
    bin: string;
    /**
     * Hexadecimal representation of instruction
     * @type String
     */
    hex: string;
    /**
     * Fragments for assembly instruction rendering, ordered by token position
     * @type Array
     */
    asmFrags: any[];
    /**
     * Fragments for binary instruction rendering, ordered by bit position
     * @type Array
     */
    binFrags: any[];
    #private;
}
/**
 * Represents a fragment of the instruction
 * @class
 */
export class Frag {
    constructor(id: any, asm: any, bits: any, field: any, mem?: boolean);
    /** Fragment ID (e.g. FRAG.OPC, FRAG.RS1, etc.)
     * @type {Number}
     */
    id: number;
    /** Assembly fragment (e.g., 'addi', 'x5', etc.)
     * @type {String}
     */
    asm: string;
    /** Bits fragment (e.g., '00101')
     * @type {String}
     */
    bits: string;
    /** Name of field (e.g., 'opcode', 'rs1', etc.)
     * @type {String}
     */
    field: string;
    /** Signals fragment is a memory address
     * @type {Boolean}
     */
    mem: boolean;
}

✄
var t,i,e,s,r,n,a=this&&this.__classPrivateFieldSet||function(t,i,e,s,r){if("m"===s)throw new TypeError("Private method is not writable");if("a"===s&&!r)throw new TypeError("Private accessor was defined without a setter");if("function"==typeof i?t!==i||!r:!i.has(t))throw new TypeError("Cannot write private member to an object whose class did not declare it");return"a"===s?r.call(t,e):r?r.value=e:i.set(t,e),e},o=this&&this.__classPrivateFieldGet||function(t,i,e,s){if("a"===e&&!s)throw new TypeError("Private accessor was defined without a getter");if("function"==typeof i?t!==i||!s:!i.has(t))throw new TypeError("Cannot read private member from an object whose class did not declare it");return"m"===e?s:"a"===e?s.call(t):s?s.value:i.get(t)};import{BASE as h,ISA as c}from"./Constants.js";import{configDefault as f}from"./Config.js";import{Decoder as l,decRegAbi as m}from"./Decoder.js";import{Encoder as d}from"./Encoder.js";export class Instruction{constructor(r,n={}){t.add(this),i.set(this,void 0),e.set(this,void 0),a(this,i,Object.assign({},f,n),"f"),o(this,t,"m",s).call(this,r.trim())}}i=new WeakMap,e=new WeakMap,t=new WeakSet,s=function(i){if(i.trimStart().split(" ")[0]in c)o(this,t,"m",n).call(this,i);else if(/^(0b)?[01]{1,32}$/.test(i))this.bin=convertBase(i,h.bin,h.bin,32);else if(/^(0x)?[0-9a-fA-F]{1,8}$/.test(i))this.bin=convertBase(i,h.hex,h.bin,32);else{if(!/^[a-zA-Z]$/.test(i[0]))throw"Invalid instruction (not in binary, hexadecimal, nor assembly)";o(this,t,"m",n).call(this,i)}o(this,t,"m",r).call(this);let e=8;this.asm.startsWith("c.")&&(e=4),this.hex=convertBase(this.bin,h.bin,h.hex,e)},r=function(){let t=new l(this.bin,o(this,i,"f"),o(this,e,"f"));this.asm=t.asm,this.asmFrags=t.asmFrags,this.binFrags=t.binFrags,this.fmt=t.fmt,this.isa=t.isa},n=function(t){let s=new d(t,o(this,i,"f"));this.bin=s.bin,a(this,e,s.xlens,"f")};export function convertBase(t,i,e,s){return parseInt(t,i).toString(e).padStart(s,"0")}export function convertRegToAbi(t){const i=/^[xf](\d+)$/.exec(t);if(null!==i){const e="f"===t[0],s=i[1];t=m(s,e)}return t}export class Frag{constructor(t,i,e,s,r=!1){this.id=t,this.asm=i,this.bits=e,this.field=s,this.mem=r}}
