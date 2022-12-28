//! Example to showcase use of different, fine-grained analysis in radare.

extern crate r2api;
extern crate r2pipe;
extern crate serde_json;

use r2api::api_trait::R2Api;
use r2pipe::r2::R2;

fn main() {
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_all().unwrap();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_and_autoname().unwrap();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_function_calls().unwrap();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_data_references().unwrap();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_references_esil().unwrap();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_function_preludes().unwrap();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_function_references().unwrap();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_symbols().unwrap();
        println!("{:#?}", r2.fn_list());
    }
    {
        let path = "/bin/ls";
        let mut r2 = R2::new(Some(path)).expect("Failed to spawn r2");
        r2.analyze_consecutive_functions().unwrap();
        println!("{:#?}", r2.fn_list());
    }
}
