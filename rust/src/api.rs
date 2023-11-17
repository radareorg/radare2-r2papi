use crate::api_trait::R2PApi;
use crate::structs::*;

pub use r2pipe::r2::R2;
use r2pipe::Error;
use serde_json::from_str;
use std::collections::HashMap;

use std::fmt;

struct HexSlice<'a>(&'a [u8]);

impl<'a> HexSlice<'a> {
    fn new<T>(data: &'a T) -> HexSlice<'a>
    where
        T: ?Sized + AsRef<[u8]> + 'a,
    {
        HexSlice(data.as_ref())
    }
}

// You can choose to implement multiple traits, like Lower and UpperHex
impl fmt::Display for HexSlice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            // Decide if you want to pad the value or have spaces inbetween, etc.
            write!(f, "{:02X} ", byte)?;
        }
        Ok(())
    }
}

impl R2PApi for R2 {
    fn analyze(&mut self) -> Result<(), Error> {
        self.send("aaa")?;
        self.flush();
        Ok(())
    }

    fn init(&mut self) -> Result<(), Error> {
        self.send("e asm.esil = true")?;
        self.send("e scr.color = false")?;
        //self.send("e bin.cache = true")?;
        Ok(())
    }

    fn function<T: AsRef<str>>(&mut self, func: T) -> Result<LFunctionInfo, Error> {
        let func_name = func.as_ref();
        let cmd = format!("pdfj @ {}", func_name);
        self.send(&cmd)?;
        let raw_json = self.recv();
        // Handle Error here.
        from_str(&raw_json).map_err(Error::SerdeError)
    }

    /// change file to write mode
    fn write_mode(&mut self) -> Result<(), Error> {
        self.send("oo+")?;
        Ok(())
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

    fn arch(&mut self) -> Result<LArch, Error> {
        self.send("iAj")?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    fn set_arch(&mut self, arch: &str) -> Result<(), Error> {
        self.send(&format!("e anal.arch={}", arch))?;
        Ok(())
    }

    fn set_bits(&mut self, bits: u8) -> Result<(), Error> {
        self.send(&format!("e arch.bits={}", bits))?;
        Ok(())
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

    fn entry(&mut self) -> Result<Vec<LEntry>, Error> {
        self.send("iej")?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    fn imports(&mut self) -> Result<Vec<LImportInfo>, Error> {
        self.send("iij")?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    fn exports(&mut self) -> Result<Vec<LExportInfo>, Error> {
        self.send("iEj")?;
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

    /// seek(None) and seek(Some(addr))
    fn seek(&mut self, addr: Option<u64>) -> Result<u64, Error> {
        let seek_obj: Vec<Seek> = match addr {
            Some(addr) => {
                self.send(&format!("sj 0x{:x}", addr)).unwrap();
                from_str(&self.recv()).map_err(Error::SerdeError).unwrap()
            }
            None => {
                self.send("sj").unwrap();
                from_str(&self.recv()).map_err(Error::SerdeError).unwrap()
            }
        };

        Ok(seek_obj[0].offset.unwrap())
    }

    /// Get different types of hashes
    fn hashes(&mut self) -> Result<Hashes, Error> {
        self.send("itj")?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    /// Get the list of segment objects
    fn segments(&mut self) -> Result<Vec<Segment>, Error> {
        self.send("iSSj")?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    /// Guess the binary size
    fn size(&mut self) -> Result<u64, Error> {
        self.send("iZj")?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    /// Read n amout of bytes from a specified offset, or None for current position.
    fn read_bytes(&mut self, n: u64, offset: Option<u64>) -> Result<Vec<u8>, Error> {
        match offset {
            Some(off) => self.send(&format!("pxj {} @{}", n, off))?,
            None => self.send(&format!("pxj {}", n))?,
        }
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    /// Write bytes to a specified offset, or None for current position
    fn write_bytes(&mut self, offset: Option<u64>, bytes: &[u8]) -> Result<(), Error> {
        // let hex: String = bytes.iter().map(|b| format!("{:02X}", b)).collect();
        let hex: String = format!("{}", HexSlice::new(bytes));

        match offset {
            Some(off) => self.send(&format!("wx {} @{}", hex, off))?,
            None => self.send(&format!("wx {}", hex))?,
        }
        Ok(())
    }

    /// Read u8 from a specified offset, or None for current position
    fn read_u8(&mut self, offset: Option<u64>) -> Result<u8, Error> {
        match offset {
            Some(off) => self.send(&format!("pv1d @{}", off))?,
            None => self.send("pv1d")?,
        }
        Ok(u8::from_str_radix(&self.recv().trim_end_matches('\n')[2..], 16).unwrap())
    }

    /// Read u16 little endian from a specified offset, or None for current position
    fn read_u16_le(&mut self, offset: Option<u64>) -> Result<u16, Error> {
        match offset {
            Some(off) => self.send(&format!("pv2d @{} @e:cfg.bigendian=false", off))?,
            None => self.send("pv2d @e:cfg.bigendian=false")?,
        }
        Ok(u16::from_str_radix(&self.recv().trim_end_matches('\n')[2..], 16).unwrap())
    }

    /// Read u18 little endian from a specified offset, or None for current position
    fn read_u32_le(&mut self, offset: Option<u64>) -> Result<u32, Error> {
        match offset {
            Some(off) => self.send(&format!("pv4d @{} @e:cfg.bigendian=false", off))?,
            None => self.send("pv4d @e:cfg.bigendian=false")?,
        }
        Ok(u32::from_str_radix(&self.recv().trim_end_matches('\n')[2..], 16).unwrap())
    }

    /// Read u64 little endian from a specified offset, or None for current position
    fn read_u64_le(&mut self, offset: Option<u64>) -> Result<u64, Error> {
        match offset {
            Some(off) => self.send(&format!("pv8d @{} @e:cfg.bigendian=false", off))?,
            None => self.send("pv8d @e:cfg.bigendian=false")?,
        }
        Ok(u64::from_str_radix(&self.recv().trim_end_matches('\n')[2..], 16).unwrap())
    }

    /// Read u16 big endian from a specified offset, or None for current position
    fn read_u16_be(&mut self, offset: Option<u64>) -> Result<u16, Error> {
        match offset {
            Some(off) => self.send(&format!("pv2d @{} @e:cfg.bigendian=true", off))?,
            None => self.send("pv2d @e:cfg.bigendian=true")?,
        }
        Ok(u16::from_str_radix(&self.recv().trim_end_matches('\n')[2..], 16).unwrap())
    }

    /// Read u18 big endian from a specified offset, or None for current position
    fn read_u32_be(&mut self, offset: Option<u64>) -> Result<u32, Error> {
        match offset {
            Some(off) => self.send(&format!("pv4d @{} @e:cfg.bigendian=true", off))?,
            None => self.send("pv4d @e:cfg.bigendian=true")?,
        }
        Ok(u32::from_str_radix(&self.recv().trim_end_matches('\n')[2..], 16).unwrap())
    }

    /// Read u64 big endian from a specified offset, or None for current position
    fn read_u64_be(&mut self, offset: Option<u64>) -> Result<u64, Error> {
        match offset {
            Some(off) => self.send(&format!("pv8d @{} @e:cfg.bigendian=true", off))?,
            None => self.send("pv8d @e:cfg.bigendian=true")?,
        }
        Ok(u64::from_str_radix(&self.recv().trim_end_matches('\n')[2..], 16).unwrap())
    }

    /// Write u8 from a specified offset, or None for current position
    fn write_u8(&mut self, offset: Option<u64>, value: u8) -> Result<(), Error> {
        match offset {
            Some(off) => self.send(&format!("wv1 {} @{}", value, off))?,
            None => self.send(&format!("wv1 {}", value))?,
        }
        Ok(())
    }

    /// Write u16 little endian from a specified offset, or None for current position
    fn write_u16_le(&mut self, offset: Option<u64>, value: u16) -> Result<(), Error> {
        match offset {
            Some(off) => self.send(&format!("wv2 {} @{} @e:cfg.bigendian=false", value, off))?,
            None => self.send(&format!("wv2 {} @e:cfg.bigendian=false", value))?,
        }
        Ok(())
    }

    /// Write u18 little endian from a specified offset, or None for current position
    fn write_u32_le(&mut self, offset: Option<u64>, value: u32) -> Result<(), Error> {
        match offset {
            Some(off) => self.send(&format!("wv4 {} @{} @e:cfg.bigendian=false", value, off))?,
            None => self.send(&format!("wv4 {} @e:cfg.bigendian=false", value))?,
        }
        Ok(())
    }

    /// Write u64 little endian from a specified offset, or None for current position
    fn write_u64_le(&mut self, offset: Option<u64>, value: u64) -> Result<(), Error> {
        match offset {
            Some(off) => self.send(&format!("wv8 {} @{} @e:cfg.bigendian=false", value, off))?,
            None => self.send(&format!("wv8 {} @e:cfg.bigendian=false", value))?,
        }
        Ok(())
    }

    /// Write u16 big endian from a specified offset, or None for current position
    fn write_u16_be(&mut self, offset: Option<u64>, value: u16) -> Result<(), Error> {
        match offset {
            Some(off) => self.send(&format!("wv2 {} @{} @e:cfg.bigendian=true", value, off))?,
            None => self.send(&format!("wv2 {} @e:cfg.bigendian=true", value))?,
        }
        Ok(())
    }

    /// Write u18 big endian from a specified offset, or None for current position
    fn write_u32_be(&mut self, offset: Option<u64>, value: u32) -> Result<(), Error> {
        match offset {
            Some(off) => self.send(&format!("wv4 {} @{} @e:cfg.bigendian=true", value, off))?,
            None => self.send(&format!("wv4 {} @e:cfg.bigendian=true", value))?,
        }
        Ok(())
    }

    /// Write u64 big endian from a specified offset, or None for current position
    fn write_u64_be(&mut self, offset: Option<u64>, value: u64) -> Result<(), Error> {
        match offset {
            Some(off) => self.send(&format!("wv8 {} @{} @e:cfg.bigendian=true", value, off))?,
            None => self.send(&format!("wv8 {} @e:cfg.bigendian=true", value))?,
        }
        Ok(())
    }

    /// Init esil emulator
    fn esil_init(&mut self) -> Result<(), Error> {
        self.send("aei")?;
        self.send("aeim")?;
        self.send("aeip")?;
        self.send("e dbg.trace=true")?;
        Ok(())
    }

    /// Get esil registers
    fn esil_regs(&mut self) -> Result<LRegInfo, Error> {
        self.send("aerpj")?;
        let raw_json = self.recv();
        from_str(&raw_json).map_err(Error::SerdeError)
    }

    /// Set specific esil register value
    fn esil_set_reg(&mut self, reg: &str, value: u64) -> Result<(), Error> {
        self.send(&format!("aer {}={}", reg, value))?;
        Ok(())
    }

    /// Get specific register value
    fn esil_get_reg(&mut self, regname: &str) -> Result<u64, Error> {
        self.send(&format!("aer {}", regname))?;
        let n = u64::from_str_radix(&self.recv().trim_end_matches('\n')[2..], 16).unwrap();
        Ok(n)
    }

    /// Emulate single step
    fn esil_step(&mut self) -> Result<(), Error> {
        self.send("aes")?;
        Ok(())
    }

    /// Emulate step over
    fn esil_step_over(&mut self) -> Result<(), Error> {
        self.send("aeso")?;
        Ok(())
    }

    /// Emulate back step.
    fn esil_step_back(&mut self) -> Result<(), Error> {
        self.send("aesb")?;
        Ok(())
    }

    /// Emulate until address.
    fn esil_step_until_addr(&mut self, addr: u64) -> Result<(), Error> {
        self.send(&format!("aseou 0x{:x}", addr))?;
        Ok(())
    }

    /// Continue until exception.
    fn esil_cont_until_exception(&mut self) -> Result<(), Error> {
        self.send("aec")?;
        Ok(())
    }

    /// Continue until interrupt.
    fn esil_cont_until_int(&mut self) -> Result<(), Error> {
        self.send("aecs")?;
        Ok(())
    }

    /// Continue until call.
    fn esil_cont_until_call(&mut self) -> Result<(), Error> {
        self.send("aecc")?;
        Ok(())
    }

    /// Continue until address.
    fn esil_cont_until_addr(&mut self, addr: u64) -> Result<(), Error> {
        self.send(&format!("aecu 0x{:x}", addr))?;
        Ok(())
    }

    /// Allocate a buffer of size sz
    fn malloc(&mut self, sz: usize) -> Result<(), Error> {
        self.send(&format!("o malloc://{}", sz))?;
        Ok(())
        /*
        self.flush();
        self.send(&format!("o ~malloc://{} | tail -1", sz))?;
        let out = self.recv();
        let saddr = out.split(' ').nth(4).unwrap();
        println!("-{}-", saddr);
        Ok(u64::from_str_radix(&saddr[2..], 16).unwrap())*/
    }

    /// Get list of buffers
    fn buffers(&mut self) -> Result<Vec<Buffer>, Error> {
        self.send("oj")?;
        from_str(&self.recv()).map_err(Error::SerdeError)
    }

    /// Free buffer
    fn free(&mut self, n: u64) -> Result<(), Error> {
        self.send(&format!("o- {}", n))?;
        Ok(())
    }

    /// Set a setting
    fn set(&mut self, key: &str, value: &str) -> Result<(), Error> {
        self.send(&format!("e {} = {}", key, value))?;
        Ok(())
    }

    /// Get setting  
    fn get(&mut self, key: &str) -> Result<String, Error> {
        self.send("ej")?;
        let data = self.recv();
        let evalj = from_str::<HashMap<&str, String>>(&data).map_err(Error::SerdeError)?;
        let value = evalj.get(key).unwrap();
        let value2 = value.to_string();
        Ok(value2)
    }
}
