extern crate r2papi;
extern crate r2pipe;
extern crate serde_json;

use r2papi::api_trait::R2PApi;
use r2pipe::r2::R2;

fn main() {
    let path = "/bin/ls";
    let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
    r2.init().unwrap();
    r2.analyze().unwrap();

    //println!("malloc {:#?}", r2.malloc(1024));
    println!("arch {:#?}", r2.arch());
    println!("reg_info {:#?}", r2.reg_info());
    println!("bin_info {:#?}", r2.bin_info());
    println!("flag_info {:#?}", r2.flag_info());
    println!("fn_list {:#?}", r2.fn_list());
    println!("symbols {:#?}", r2.symbols());
    println!("entry {:#?}", r2.entry());
    println!("import {:#?}", r2.imports());
    println!("exports {:#?}", r2.exports());
    println!("relogs {:#?}", r2.relocs());
    println!("libraries {:#?}", r2.libraries());
    println!("seek1 {:#?}", r2.seek(None));
    println!("seek2 {:#?}", r2.seek(Some(0x123)));
    println!("hashes {:#?}", r2.hashes());
    println!("segments {:#?}", r2.segments());
    println!("size {:#?}", r2.size());
    println!("read_bytes {:#?}", r2.read_bytes(4, None));
    //println!("read_bits {:#?}", r2.read_bits(4, None));
    //r2.write_bytes(None, &[0x41,0x41,0x41,0x41]).unwrap();
    //r2.write_bytes(Some(0x11223344), &[0x41,0x41,0x41,0x41]).unwrap();
    println!("read u8 {:#?}", r2.read_u8(None));
    println!("read u16 le {:#?}", r2.read_u16_le(None));
    println!("read u32 le {:#?}", r2.read_u32_le(None));
    println!("read u64 le {:#?}", r2.read_u64_le(None));
    println!("read u16 be {:#?}", r2.read_u16_be(None));
    println!("read u32 be {:#?}", r2.read_u32_be(None));
    println!("read u64 be {:#?}", r2.read_u64_be(None));
    /*
    println!("write u8 {:#?}", r2.write_u8(None, 0x41));
    println!("write u16 le {:#?}", r2.write_u16_le(None, 0x4141));
    println!("write u32 le {:#?}", r2.write_u32_le(None, 0x41414141));
    println!("write u64 le {:#?}", r2.write_u64_le(None, 0x41414141_41414141));
    println!("write u16 be {:#?}", r2.write_u16_be(None, 0x4141));
    println!("write u32 be {:#?}", r2.write_u32_be(None, 0x41414141));
    println!("write u64 be {:#?}", r2.write_u64_be(None, 0x41414141_41414141));
    */

    r2.esil_init().expect("cannot initialize esil");
    let esil_regs = r2.esil_regs().unwrap();
    println!("esil regs: {:#?}", esil_regs);
    let mut pc = r2.esil_get_reg("pc").unwrap();
    println!("esil pc: 0x{:x}", pc);
    r2.esil_set_reg("pc", pc).unwrap();
    r2.esil_step().unwrap();
    r2.esil_step_over().unwrap();
    r2.esil_step_back().unwrap();
    r2.esil_step_until_addr(pc + 20).unwrap();
    r2.esil_cont_until_int().unwrap();
    r2.esil_cont_until_call().unwrap();
    r2.esil_cont_until_exception().unwrap();
    pc = r2.esil_get_reg("pc").unwrap();
    r2.esil_cont_until_addr(pc + 20).unwrap();
    r2.set_arch("arm").unwrap();
    r2.set_bits(64).unwrap();

    r2.malloc(1024).unwrap();
    println!("buffers: {:#?}", r2.buffers());
    r2.free(5).unwrap();
    r2.set("dbg.bpsize", "4").unwrap();
    println!("dbg.bpsize: {:#?}", r2.get("dbg.bpsize"));
}
