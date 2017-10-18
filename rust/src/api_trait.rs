use structs::*;

use serde_json::Error;
// Maybe have r2api-rs' own error type?

pub trait R2Api {
    /// Initialize r2 instance with some basic configurations
    fn init(&mut self);

    /// Run r2-based analysis on the file to extract information
    fn analyze(&mut self);

    /// Detect a function at a particular address in the binary
    fn function<T: AsRef<str>>(&mut self, T) -> Result<LFunctionInfo, Error>;

    /// Get a Vec of a certain number of instruction objects at an offset in the binary
    fn insts<T: AsRef<str>>(&mut self, Option<u64>, Option<T>) -> Result<Vec<LOpInfo>, Error>;

    /// Get register information
    fn reg_info(&mut self) -> Result<LRegInfo, Error>;

    /// Get flag information
    fn flag_info(&mut self) -> Result<Vec<LFlagInfo>, Error>;

    /// Get binary information
    fn bin_info(&mut self) -> Result<LBinInfo, Error>;

    /// Get list of functions
    fn fn_list(&mut self) -> Result<Vec<FunctionInfo>, Error>;

    /// Get calling convention information for registers
    fn cc_info(&mut self) -> Result<LCCInfo, Error>;

    /// Get list of sections
    fn sections(&mut self) -> Result<Vec<LSectionInfo>, Error>;

    /// Get list of strings
    fn strings(&mut self, bool) -> Result<Vec<LStringInfo>, Error>;

    /// Get list of local variables in function defined at a particular address
    fn locals_of(&mut self, u64) -> Result<Vec<LVarInfo>, Error>;

    /// Get a list of all symbols defined in the binary
    fn symbols(&mut self) -> Result<Vec<LSymbolInfo>, Error>;
}

