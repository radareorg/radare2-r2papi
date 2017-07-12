extern crate r2pipe;
extern crate r2api;

use r2pipe::r2::R2;
use r2api::api_trait::R2Api;

fn main() {
    let path = "/home/chinmay_dd/Projects/zz/rune/bins/a.out";
    let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
    r2.init();

    println!("{:#?}", r2.fn_list().expect("Failed to get function data."));
}
