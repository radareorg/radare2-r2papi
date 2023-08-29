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

    r2.set_arch("arm").unwrap();
    r2.set_bits(64).unwrap();
}
