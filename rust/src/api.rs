use structs::*;
use api_trait::R2Api;

use r2pipe::r2::R2;
use serde_json::{Error, from_str};

impl R2Api for R2 {
    fn analyze(&mut self) {
        self.send("aaa");
        self.flush();
    }

    fn init(&mut self) {
        self.send("e asm.esil = true");
        self.send("e scr.color = false");
        self.analyze();
    }

    fn function<T: AsRef<str>>(&mut self, func: T) -> Result<LFunctionInfo, Error> {
        let func_name = func.as_ref();
        let cmd = format!("pdfj @ {}", func_name);
        self.send(&cmd);
        let raw_json = self.recv();
        // Handle Error here.
        from_str(&raw_json)
    }

    // get 'n' (or 16) instructions at 'offset' (or current position if offset in
    // `None`)
    fn insts<T: AsRef<str>>(&mut self, n: Option<u64>, offset: Option<T>) -> Result<Vec<LOpInfo>, Error> {
        let n = n.unwrap_or(16);
        let mut cmd = format!("pdj{}", n);
        if let Some(o) = offset {
            cmd = format!("{} @ {}", cmd, o.as_ref());
        }
        self.send(&cmd);
        let raw_json = self.recv();
        from_str(&raw_json)
    }

    fn reg_info(&mut self) -> Result<LRegInfo, Error> {
        self.send("drpj");
        let raw_json = self.recv();
        from_str(&raw_json)
    }

    fn flag_info(&mut self) -> Result<Vec<LFlagInfo>, Error> {
        self.send("fj");
        let raw_json = self.recv();
        from_str(&raw_json)
    }

    fn bin_info(&mut self) -> Result<LBinInfo, Error> {
        self.send("ij");
        let raw_json = self.recv();
        from_str(&raw_json)
    }

    fn locals_of(&mut self, location: u64) -> Result<Vec<LVarInfo>, Error> {
        self.send(&format!("afvbj @ {}", location));
        let x: Result<Vec<LVarInfo>, Error> = from_str(&self.recv());
        x
    }

    fn fn_list(&mut self) -> Result<Vec<FunctionInfo>, Error> {
        self.send("aflj");
        let raw_json = self.recv();
        let mut finfo: Result<Vec<FunctionInfo>, Error> = from_str::<Vec<FunctionInfo>>(&raw_json);
        if let Ok(ref mut fns) = finfo {
            for f in fns.iter_mut() {
                let res = self.locals_of(f.offset.unwrap());
                if res.is_ok() {
                    f.locals = res.ok();
                } else {
                    f.locals = Some(Vec::new());
                }
            }
        }
        finfo
    }

    fn sections(&mut self) -> Result<Vec<LSectionInfo>, Error> {
        self.send("Sj");
        from_str(&self.recv())
    }

    fn strings(&mut self, data_only: bool) -> Result<Vec<LStringInfo>, Error> {
        if data_only {
            self.send("izj");
            from_str(&self.recv())
        } else {
            self.send("izzj");
            let x: Result<Vec<LStringInfo>, Error> = from_str(&self.recv());
            x
        }
    }

}

