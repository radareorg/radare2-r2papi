use crate::api_trait::R2Api;
use crate::structs::*;

use r2pipe::r2::R2;
use serde_json::{from_str, Error};

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

    fn disassemble_n_bytes(&mut self, n: u64, offset: Option<u64>) -> Result<Vec<LOpInfo>, Error> {
        self.send(&format!(
            "pDj {} @ {}",
            n,
            offset.map(|x| x.to_string()).unwrap_or("".to_owned())
        ));
        let s = &self.recv();
        from_str(s)
    }

    fn disassemble_n_insts(&mut self, n: u64, offset: Option<u64>) -> Result<Vec<LOpInfo>, Error> {
        self.send(&format!(
            "pdj {} @ {}",
            n,
            offset.map(|x| x.to_string()).unwrap_or("".to_owned())
        ));
        from_str(&self.recv())
    }

    // get 'n' (or 16) instructions at 'offset' (or current position if offset in
    // `None`)
    fn insts<T: AsRef<str>>(
        &mut self,
        n: Option<u64>,
        offset: Option<T>,
    ) -> Result<Vec<LOpInfo>, Error> {
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

    fn cc_info_of(&mut self, location: u64) -> Result<LCCInfo, Error> {
        self.send(&format!("afcrj @ {}", location));
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
        self.send("iSj");
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

    fn imports(&mut self) -> Result<Vec<LImportInfo>, Error> {
        self.send("iij");
        from_str(&self.recv())
    }

    fn exports(&mut self) -> Result<Vec<LExportInfo>, Error> {
        self.send("iej");
        from_str(&self.recv())
    }

    fn symbols(&mut self) -> Result<Vec<LSymbolInfo>, Error> {
        self.send("isj");
        from_str(&self.recv())
    }

    fn relocs(&mut self) -> Result<Vec<LRelocInfo>, Error> {
        self.send("irj");
        from_str(&self.recv())
    }

    fn entrypoint(&mut self) -> Result<Vec<LEntryInfo>, Error> {
        self.send("iej");
        from_str(&self.recv())
    }

    fn libraries(&mut self) -> Result<Vec<String>, Error> {
        self.send("ilj");
        from_str(&self.recv())
    }

    // Send a raw command and recv output
    fn raw(&mut self, cmd: String) -> String {
        self.send(&cmd);
        self.recv()
    }

    /// All Analysis
    fn analyze_all(&mut self) {
        self.send("aa");
        self.recv();
    }

    /// Analyze and auto-name functions
    fn analyze_and_autoname(&mut self) {
        self.send("aaa");
        self.recv();
    }

    /// Analyze function calls
    fn analyze_function_calls(&mut self) {
        self.send("aac");
        self.recv();
    }

    /// Analyze data references
    fn analyze_data_references(&mut self) {
        self.send("aad");
        self.recv();
    }

    /// Analyze references esil
    fn analyze_references_esil(&mut self) {
        self.send("aae");
        self.recv();
    }

    /// Find and analyze function preludes
    fn analyze_function_preludes(&mut self) {
        self.send("aap");
        self.recv();
    }

    /// Analyze instruction references
    fn analyze_function_references(&mut self) {
        self.send("aar");
        self.recv();
    }

    /// Analyze symbols
    fn analyze_symbols(&mut self) {
        self.send("aas");
        self.recv();
    }

    /// Analyze consecutive functions in section
    fn analyze_consecutive_functions(&mut self) {
        self.send("aat");
        self.recv();
    }
}
