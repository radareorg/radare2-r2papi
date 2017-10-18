use structs::*;

use serde_json::Error;
// Maybe have r2api-rs' own error type?

pub trait R2Api {
    /// Initialize r2 instance with some basic configurations
    fn init(&mut self);

    /// Run r2-based analysis on the file to extract information
    fn analyze(&mut self);

    //////////////////////////////////////////////
    //// Architecture/OS Information
    /////////////////////////////////////////////
    /// Get register information
    fn reg_info(&mut self) -> Result<LRegInfo, Error>;
    /// Get binary information
    fn bin_info(&mut self) -> Result<LBinInfo, Error>;
    /// Get calling convention information for registers
    fn cc_info(&mut self) -> Result<LCCInfo, Error>;


    //////////////////////////////////////////////
    //// Binary/Loader Initialized Information
    //////////////////////////////////////////////
    /// Get a list of all symbols defined in the binary
    fn symbols(&mut self) -> Result<Vec<LSymbolInfo>, Error>;
    /// Get a list of all imports for this binary
    fn imports(&mut self) -> Result<Vec<LImportInfo>, Error>;
    /// Get a list of all exports by this binary
    fn exports(&mut self) -> Result<Vec<LExportInfo>, Error>;
    /// Get list of sections
    fn sections(&mut self) -> Result<Vec<LSectionInfo>, Error>;
    /// Get relocations
    fn relocs(&mut self) -> Result<Vec<LRelocInfo>, Error>;
    /// Get entry point for loaded binary
    fn entrypoint(&mut self) -> Result<Vec<LEntryInfo>, Error>;
    /// Shared libraries
    fn libraries(&mut self) -> Result<Vec<String>, Error>;


    ///////////////////////////////////////////////
    //// Analysis Information
    ///////////////////////////////////////////////
    /// Get flag information
    fn flag_info(&mut self) -> Result<Vec<LFlagInfo>, Error>;
    /// Get list of functions
    fn fn_list(&mut self) -> Result<Vec<FunctionInfo>, Error>;
    /// Get list of strings
    fn strings(&mut self, bool) -> Result<Vec<LStringInfo>, Error>;
    /// Get list of local variables in function defined at a particular address
    fn locals_of(&mut self, u64) -> Result<Vec<LVarInfo>, Error>;
    /// Detect a function at a particular address in the binary
    fn function<T: AsRef<str>>(&mut self, T) -> Result<LFunctionInfo, Error>;


    /////////////////////////////////////////////////
    //// Disassembly Information
    /////////////////////////////////////////////////
    /// Get a Vec of a certain number of instruction objects at an offset in the binary
    fn insts<T: AsRef<str>>(&mut self, Option<u64>, Option<T>) -> Result<Vec<LOpInfo>, Error>;
}
