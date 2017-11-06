//! Example to showcase use of different, fine-grained analysis in radare.

extern crate r2pipe;
extern crate r2api;
extern crate serde_json;

use r2pipe::r2::R2;
use r2api::api_trait::R2Api;


fn main() {
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_all();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_and_autoname();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_function_calls();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_data_references();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_references_esil();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_function_preludes();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_function_references();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_symbols();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_consecutive_functions();
        println!("{:#?}", r2.fn_list());
    }
}
