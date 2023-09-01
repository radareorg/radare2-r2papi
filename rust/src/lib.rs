//! Add example usage here.

#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

extern crate libc;
extern crate r2pipe;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

#[macro_use]
pub mod api;
pub mod api_trait;
pub mod structs;

#[cfg(test)]
mod tests {
    use super::*;
    use api_trait::R2PApi;

    #[test]
    fn lib_tests() {
        let mut r2 = api::R2::new(Some("malloc://1024")).unwrap();
        r2.init().unwrap();
        r2.write_bytes(Some(0), &[0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48]).unwrap();
        assert!(r2.read_u8(Some(0)).unwrap() == 0x41);
        assert!(r2.read_u16_le(Some(0)).unwrap() == 0x4241);
        assert!(r2.read_u16_be(Some(0)).unwrap() == 0x4142);
        assert!(r2.read_u32_le(Some(0)).unwrap() == 0x44434241);
        assert!(r2.read_u32_be(Some(0)).unwrap() == 0x41424344);
        assert!(r2.read_u64_le(Some(0)).unwrap() == 0x48474645_44434241);
        r2.seek(Some(0)).unwrap();
        assert!(r2.read_u64_be(None).unwrap() == 0x41424344_45464748);
        let bytes = r2.read_bytes(8, Some(0)).unwrap();
        assert!(bytes[0] == 0x41 && bytes[7] == 0x48);


        /*
        r2.analyze().unwrap();
        assert!(r2.arch().unwrap().bins[0].bits == Some(64));
        assert!(r2.imports().unwrap().len() > 50);
        assert!(r2.exports().unwrap().len() > 10);
        let afl = r2.fn_list().unwrap();
        assert!(afl.len() > 200);
        assert!(afl[0].name == Some("entry0".to_string())); 
        assert!(1 == 1);*/
    }
}
