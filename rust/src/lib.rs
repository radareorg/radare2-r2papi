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
        let mut r2 = api::R2::new(Some("/bin/ls")).unwrap();
        r2.init().unwrap();
        r2.analyze().unwrap();
        assert!(r2.arch().unwrap().bins[0].bits == Some(64));
        assert!(r2.imports().unwrap().len() == 112);
        assert!(r2.exports().unwrap().len() == 13);
        let afl = r2.fn_list().unwrap();
        assert!(afl.len() > 200);
        assert!(afl[0].name == Some("entry0".to_string()));
    }
}
