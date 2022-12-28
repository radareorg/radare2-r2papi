use crate::structs::*;
use r2pipe::Error;

// Maybe have r2api-rs' own error type?

pub trait R2Api {
    /// Initialize r2 instance with some basic configurations
    fn init(&mut self) -> Result<(), Error>;

    // Recv raw output
    fn raw(&mut self, cmd: String) -> Result<String, Error>;

    /// Run r2-based analysis on the file to extract information
    fn analyze(&mut self) -> Result<(), Error>;

    //////////////////////////////////////////////
    //// Architecture/OS Information
    /////////////////////////////////////////////
    /// Get register information
    fn reg_info(&mut self) -> Result<LRegInfo, Error>;
    /// Get binary information
    fn bin_info(&mut self) -> Result<LBinInfo, Error>;

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

    ///////////////////////////////////////////////////////////////////
    //// Analysis functions to initialize/perform specific analysis
    //////////////////////////////////////////////////////////////////
    // TODO: Have options to set timeouts, also make it non-blocking if possible to hide latency of
    // these analysis. Then, these can be called early on the chain, perform other non-related
    // operations while analysis happens and finally, wait on the results.
    /// All Analysis
    fn analyze_all(&mut self) -> Result<(), Error>;
    /// Analyze and auto-name functions
    fn analyze_and_autoname(&mut self) -> Result<(), Error>;
    /// Analyze function calls
    fn analyze_function_calls(&mut self) -> Result<(), Error>;
    /// Analyze data references
    fn analyze_data_references(&mut self) -> Result<(), Error>;
    /// Analyze references esil
    fn analyze_references_esil(&mut self) -> Result<(), Error>;
    /// Find and analyze function preludes
    fn analyze_function_preludes(&mut self) -> Result<(), Error>;
    /// Analyze instruction references
    fn analyze_function_references(&mut self) -> Result<(), Error>;
    /// Analyze symbols
    fn analyze_symbols(&mut self) -> Result<(), Error>;
    /// Analyze consecutive functions in section
    fn analyze_consecutive_functions(&mut self) -> Result<(), Error>;

    ///////////////////////////////////////////////
    //// Analysis Information
    ///////////////////////////////////////////////
    /// Get flag information
    fn flag_info(&mut self) -> Result<Vec<LFlagInfo>, Error>;
    /// Get list of functions
    fn fn_list(&mut self) -> Result<Vec<FunctionInfo>, Error>;
    /// Get list of strings
    fn strings(&mut self, data_only: bool) -> Result<Vec<LStringInfo>, Error>;
    /// Get list of local variables in function defined at a particular address
    fn locals_of(&mut self, location: u64) -> Result<Vec<LVarInfo>, Error>;
    /// Get calling convention information for a function defined at a particular address
    fn cc_info_of(&mut self, location: u64) -> Result<LCCInfo, Error>;
    /// Detect a function at a particular address in the binary
    fn function<T: AsRef<str>>(&mut self, func: T) -> Result<LFunctionInfo, Error>;

    /////////////////////////////////////////////////
    //// Disassembly Information
    /////////////////////////////////////////////////
    /// Get a Vec of a certain number of instruction objects at an offset in the binary
    fn insts<T: AsRef<str>>(
        &mut self,
        n: Option<u64>,
        offset: Option<T>,
    ) -> Result<Vec<LOpInfo>, Error>;
    fn disassemble_n_bytes(&mut self, n: u64, offset: Option<u64>) -> Result<Vec<LOpInfo>, Error>;
    fn disassemble_n_insts(&mut self, n: u64, offset: Option<u64>) -> Result<Vec<LOpInfo>, Error>;
}
