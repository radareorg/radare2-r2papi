import { R2PipeAsync } from "./index";
import { EsilParser } from "./esil";

declare let r2: R2PipeAsync;
declare let r2plugin: any;
/// ========== main =========== ///

const ep = new EsilParser(r2);

/*
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
    ep.parse("1,?{,x0,}{,x1,},:=");
    ep.parse("zf,!,nf,vf,^,!,&,?{,4294982284,pc,:=,}");
}

async function pdq(arg: string) {
    r2.cmd("e cfg.json.num=string");
    switch (arg[0]) {
        case " ":
            await parseAmount(+arg);
            break;
        case "i":
            await parseAmount(1);
            break;
        case "f":
        case undefined:
        case "":
            {
                const oaddr = (await r2.cmd("?v $$")).trim();
                // const func = r2.cmdj("pdrj"); // XXX this command changes the current seek
                const bbs = await r2.cmdj("afbj"); // XXX this command changes the current seek
                for (const bb of bbs) {
                    console.log("bb_" + bb.addr + ":");
                    r2.cmd(`s ${bb.addr}`);
                    await parseAmount(bb.ninstr);
                }
                r2.cmd(`s ${oaddr}`);
            }
            break;
        case "e":
            ep.reset();
            ep.parse(arg.slice(1).trim(), await r2.cmd("?v $$"));
            console.log(ep.toString());
            break;
        case "t":
            testComplex();
            testBasic();
            testConditional();
            testLoop();
            console.log(ep.toString());
            console.log("---");
            console.log(ep.toEsil());
            break;
        case "?":
            console.log("Usage: pdq[ef?] [ninstr] - quick decompiler plugin");
            console.log("pdq           - decompile current function");
            console.log("pdq 100       - decompile 100 instructions");
            console.log("pdqe 1,rax,:= - decompile given esil expressoin");
            console.log("pdqi          - decompile one instruction");
            console.log("pdqt          - run tests");
            break;
    }
}

async function parseAmount(n: number): Promise<void> {
    // console.log("PDQ "+n);
    const pies = await r2.cmd("pie " + n + " @e:scr.color=0");
    const lines = pies.trim().split("\n");
    for (const line of lines) {
        if (line.length === 0) {
            console.log("Empty");
            continue;
        }
        // console.log("parse", r2.cmd("?v:$$"));
        const kv = line.split(" ");
        if (kv.length > 1) {
            // line != "") {
            // console.log("// @ " + kv[0]);
            ep.reset();
            r2.cmd(`s ${kv[0]}`);
            ep.parse(kv[1], kv[0]);
            ep.optimize("flags,labels");
            console.log(ep.toString());
        }
    }
    // console.log(ep.toString());
}

r2.unload("core", "pdq");
r2.plugin("core", function () {
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
        name: "pdq",
        desc: "quick decompiler",
        call: coreCall
    };
});
