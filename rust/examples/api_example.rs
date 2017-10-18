extern crate r2pipe;
extern crate r2api;
extern crate serde_json;

use r2pipe::r2::R2;
use r2api::api_trait::R2Api;

fn main() {
    let path = "/bin/ls";
    let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
    r2.init();
    println!("{:#?}", r2.cc_info().expect("Failed to get function list."));
    println!("{:#?}", r2.symbols());
}
