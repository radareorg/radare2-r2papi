use crate::structs::*;
use r2pipe::Error;

// Maybe have r2papi-rs' own error type?

pub trait R2PApi {
    /// Initialize r2 instance with some basic configurations
    fn init(&mut self) -> Result<(), Error>;
    /// Recv raw output
    fn raw(&mut self, cmd: String) -> Result<String, Error>;
    /// Run r2-based analysis on the file to extract information
    fn analyze(&mut self) -> Result<(), Error>;
    /// Open file in write mode
    fn write_mode(&mut self) -> Result<(), Error>;

    //////////////////////////////////////////////
    //// Architecture/OS Information
    /////////////////////////////////////////////
    /// Get register information
    fn reg_info(&mut self) -> Result<LRegInfo, Error>;
    /// Get binary information
    fn bin_info(&mut self) -> Result<LBinInfo, Error>;
    /// Get architecture information
    fn arch(&mut self) -> Result<LArch, Error>;
    /// Get file hashes
    fn hashes(&mut self) -> Result<Hashes, Error>;
    /// Guess binary size
    fn size(&mut self) -> Result<u64, Error>;
    /// Change the architecture bits
    fn set_bits(&mut self, bits: u8) -> Result<(), Error>;
    /// Change the architecture type
    fn set_arch(&mut self, arch: &str) -> Result<(), Error>;

    //////////////////////////////////////////////
    //// Binary/Loader Initialized Information
    //////////////////////////////////////////////
    /// Get a list of all symbols defined in the binary
    fn symbols(&mut self) -> Result<Vec<LSymbolInfo>, Error>;
    /// Get a list of all entry points
    fn entry(&mut self) -> Result<Vec<LEntry>, Error>;
    /// Get a list of all imports for this binary
    fn imports(&mut self) -> Result<Vec<LImportInfo>, Error>;
    /// Get a list of all exports by this binary
    fn exports(&mut self) -> Result<Vec<LExportInfo>, Error>;
    /// Get list of sections
    fn sections(&mut self) -> Result<Vec<LSectionInfo>, Error>;
    /// Get relocations
    fn relocs(&mut self) -> Result<Vec<LRelocInfo>, Error>;
    /// Get shared libraries
    fn libraries(&mut self) -> Result<Vec<String>, Error>;
    /// Get segments
    fn segments(&mut self) -> Result<Vec<Segment>, Error>;

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
    fn seek(&mut self, addr: Option<u64>) -> Result<u64, Error>;

    /////////////////////////////////////////////////
    //// Read and Write Data
    /////////////////////////////////////////////////
    /// Read n amout of bytes from a specified offset, or None for current position.
    fn read_bytes(&mut self, n: u64, offset: Option<u64>) -> Result<Vec<u8>, Error>;
    /// Read n amount of bits from a specified offset, or None for current position.
    //fn read_bits(&mut self, n: u64, offset: Option<u64>) -> Result<String, Error>;
    /// Write bytes to a specified offset, or None for current position
    fn write_bytes(&mut self, offset: Option<u64>, bytes: &[u8]) -> Result<(), Error>;
    /// Read u8 from a specified offset, or None for current position
    fn read_u8(&mut self, offset: Option<u64>) -> Result<u8, Error>;
    /// Read u16 little endian from a specified offset, or None for current position
    fn read_u16_le(&mut self, offset: Option<u64>) -> Result<u16, Error>;
    /// Read u18 little endian from a specified offset, or None for current position
    fn read_u32_le(&mut self, offset: Option<u64>) -> Result<u32, Error>;
    /// Read u64 little endian from a specified offset, or None for current position
    fn read_u64_le(&mut self, offset: Option<u64>) -> Result<u64, Error>;
    /// Read u16 big endian from a specified offset, or None for current position
    fn read_u16_be(&mut self, offset: Option<u64>) -> Result<u16, Error>;
    /// Read u18 big endian from a specified offset, or None for current position
    fn read_u32_be(&mut self, offset: Option<u64>) -> Result<u32, Error>;
    /// Read u64 big endian from a specified offset, or None for current position
    fn read_u64_be(&mut self, offset: Option<u64>) -> Result<u64, Error>;
    /// Write u8 from a specified offset, or None for current position
    fn write_u8(&mut self, offset: Option<u64>, value: u8) -> Result<(), Error>;
    /// Write u16 little endian from a specified offset, or None for current position
    fn write_u16_le(&mut self, offset: Option<u64>, value: u16) -> Result<(), Error>;
    /// Write u18 little endian from a specified offset, or None for current position
    fn write_u32_le(&mut self, offset: Option<u64>, value: u32) -> Result<(), Error>;
    /// Write u64 little endian from a specified offset, or None for current position
    fn write_u64_le(&mut self, offset: Option<u64>, value: u64) -> Result<(), Error>;
    /// Write u16 big endian from a specified offset, or None for current position
    fn write_u16_be(&mut self, offset: Option<u64>, value: u16) -> Result<(), Error>;
    /// Write u18 big endian from a specified offset, or None for current position
    fn write_u32_be(&mut self, offset: Option<u64>, value: u32) -> Result<(), Error>;
    /// Write u64 big endian from a specified offset, or None for current position
    fn write_u64_be(&mut self, offset: Option<u64>, value: u64) -> Result<(), Error>;

    /////////////////////////////////////////////////
    //// Esil emulation
    /////////////////////////////////////////////////
    /// Initialize esil memory.
    fn esil_init(&mut self) -> Result<(), Error>;
    /// Get all the registers information.
    fn esil_regs(&mut self) -> Result<LRegInfo, Error>;
    /// Set specific register value.
    fn esil_set_reg(&mut self, reg: &str, value: u64) -> Result<(), Error>;
    /// Get specific register value.
    fn esil_get_reg(&mut self, reg: &str) -> Result<u64, Error>;
    /// Emulate single step.
    fn esil_step(&mut self) -> Result<(), Error>;
    /// Emulate step over.
    fn esil_step_over(&mut self) -> Result<(), Error>;
    /// Emulate back step.
    fn esil_step_back(&mut self) -> Result<(), Error>;
    /// Emulate until address.
    fn esil_step_until_addr(&mut self, addr: u64) -> Result<(), Error>;
    /// Continue until exception.
    fn esil_cont_until_exception(&mut self) -> Result<(), Error>;
    /// Continue until interrupt.
    fn esil_cont_until_int(&mut self) -> Result<(), Error>;
    /// Continue until call.
    fn esil_cont_until_call(&mut self) -> Result<(), Error>;
    /// Continue until address.
    fn esil_cont_until_addr(&mut self, addr: u64) -> Result<(), Error>;

    /////////////////////////////////////////////////
    //// Buffers
    /////////////////////////////////////////////////
    /// Allocate a buffer of size sz
    fn malloc(&mut self, sz: usize) -> Result<(), Error>;
    /// Get buffers
    fn buffers(&mut self) -> Result<Vec<Buffer>, Error>;
    /// Free buffer
    fn free(&mut self, n: u64) -> Result<(), Error>;

    /////////////////////////////////////////////////
    //// Eval
    /////////////////////////////////////////////////
    /// Set a setting (eval) set("dbg.clone", "true")
    fn set(&mut self, key: &str, value: &str) -> Result<(), Error>;
    /// Get setting  let clone = get("dbg.clone")
    fn get(&mut self, key: &str) -> Result<String, Error>;
}
