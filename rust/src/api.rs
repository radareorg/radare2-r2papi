use crate::api_trait::R2Api;
use crate::structs::*;

use r2pipe::r2::R2;
use r2pipe::Error;
use serde_json::from_str;

impl R2Api for R2 {
    fn analyze(&mut self) -> Result<(), Error> {
        self.send("aaa")?;
        self.flush();
        Ok(())
    }

    fn init(&mut self) -> Result<(), Error> {
        self.send("e asm.esil = true")?;
        self.send("e scr.color = false")?;
        self.analyze()
    }

    fn function<T: AsRef<str>>(&mut self, func: T) -> Result<LFunctionInfo, Error> {
        let func_name = func.as_ref();
        let cmd = format!("pdfj @ {}", func_name);
        self.send(&cmd)?;
        let raw_json = self.recv();
        // Handle Error here.
        from_str(&raw_json).map_err(Error::SerdeError)
    }

    fn disassemble_n_bytes(&mut self, n: u64, offset: Option<u64>) -> Result<Vec<LOpInfo>, Error> {
        self.send(&format!(
            "pDj {} @ {}",
            n,
            offset
                .map(|x| x.to_string())
                .unwrap_or_else(|| "".to_owned())
        ))?;
        let s = &self.recv();
        from_str(s).map_err(Error::SerdeError)
    }

    fn disassemble_n_insts(&mut self, n: u64, offset: Option<u64>) -> Result<Vec<LOpInfo>, Error> {
        self.send(&format!(
            "pdj {} @ {}",
            n,
            offset
                .map(|x| x.to_string())
                .unwrap_or_else(|| "".to_owned())
        ))?;
        from_str(&self.recv()).map_err(Error::SerdeError)
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
        self.send(&cmd)?;
        let raw_json = self.recv();
        from_str(&raw_json).map_err(Error::SerdeError)
    }

    fn reg_info(&mut self) -> Result<LRegInfo, Error> {
        self.send("drpj")?;
        let raw_json = self.recv();
        from_str(&raw_json).map_err(Error::SerdeError)
    }

    fn flag_info(&mut self) -> Result<Vec<LFlagInfo>, Error> {
        self.send("fj")?;
        let raw_json = self.recv();
        from_str(&raw_json).map_err(Error::SerdeError)
    }

    fn bin_info(&mut self) -> Result<LBinInfo, Error> {
        self.send("ij")?;
        let raw_json = self.recv();
        from_str(&raw_json).map_err(Error::SerdeError)
    }

    fn cc_info_of(&mut self, location: u64) -> Result<LCCInfo, Error> {
        self.send(&format!("afcrj @ {}", location))?;
        let raw_json = self.recv();
        from_str(&raw_json).map_err(Error::SerdeError)
    }

    fn locals_of(&mut self, location: u64) -> Result<Vec<LVarInfo>, Error> {
        self.send(&format!("afvbj @ {}", location))?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    fn fn_list(&mut self) -> Result<Vec<FunctionInfo>, Error> {
        self.send("aflj")?;
        let raw_json = self.recv();
        let mut finfo = from_str::<Vec<FunctionInfo>>(&raw_json).map_err(Error::SerdeError);
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
        self.send("iSj")?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    fn strings(&mut self, data_only: bool) -> Result<Vec<LStringInfo>, Error> {
        if data_only {
            self.send("izj")?;
            from_str(&self.recv()).map_err(Error::SerdeError)
        } else {
            self.send("izzj")?;
            from_str(&self.recv()).map_err(Error::SerdeError)
        }
    }

    fn imports(&mut self) -> Result<Vec<LImportInfo>, Error> {
        self.send("iij")?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    fn exports(&mut self) -> Result<Vec<LExportInfo>, Error> {
        self.send("iej")?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    fn symbols(&mut self) -> Result<Vec<LSymbolInfo>, Error> {
        self.send("isj")?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    fn relocs(&mut self) -> Result<Vec<LRelocInfo>, Error> {
        self.send("irj")?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    fn entrypoint(&mut self) -> Result<Vec<LEntryInfo>, Error> {
        self.send("iej")?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    fn libraries(&mut self) -> Result<Vec<String>, Error> {
        self.send("ilj")?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    // Send a raw command and recv output
    fn raw(&mut self, cmd: String) -> Result<String, Error> {
        self.send(&cmd)?;
        Ok(self.recv())
    }

    /// All Analysis
    fn analyze_all(&mut self) -> Result<(), Error> {
        self.send("aa")?;
        self.recv();
        Ok(())
    }

    /// Analyze and auto-name functions
    fn analyze_and_autoname(&mut self) -> Result<(), Error> {
        self.send("aaa")?;
        self.recv();
        Ok(())
    }

    /// Analyze function calls
    fn analyze_function_calls(&mut self) -> Result<(), Error> {
        self.send("aac")?;
        self.recv();
        Ok(())
    }

    /// Analyze data references
    fn analyze_data_references(&mut self) -> Result<(), Error> {
        self.send("aad")?;
        self.recv();
        Ok(())
    }

    /// Analyze references esil
    fn analyze_references_esil(&mut self) -> Result<(), Error> {
        self.send("aae")?;
        self.recv();
        Ok(())
    }

    /// Find and analyze function preludes
    fn analyze_function_preludes(&mut self) -> Result<(), Error> {
        self.send("aap")?;
        self.recv();
        Ok(())
    }

    /// Analyze instruction references
    fn analyze_function_references(&mut self) -> Result<(), Error> {
        self.send("aar")?;
        self.recv();
        Ok(())
    }

    /// Analyze symbols
    fn analyze_symbols(&mut self) -> Result<(), Error> {
        self.send("aas")?;
        self.recv();
        Ok(())
    }

    /// Analyze consecutive functions in section
    fn analyze_consecutive_functions(&mut self) -> Result<(), Error> {
        self.send("aat")?;
        self.recv();
        Ok(())
    }
}
