//! Provides structures for JSON encoding and decoding

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LOpInfo {
    pub esil: Option<String>,
    pub offset: Option<u64>,
    pub opcode: Option<String>,
    #[serde(rename = "type")]
    pub optype: Option<String>,
    pub size: Option<u64>,
    pub bytes: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LFunctionInfo {
    pub addr: Option<u64>,
    pub name: Option<String>,
    pub ops: Option<Vec<LOpInfo>>,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LRegInfo {
    pub alias_info: Vec<LAliasInfo>,
    pub reg_info: Vec<LRegProfile>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LAliasInfo {
    pub reg: String,
    pub role: u64,
    pub role_str: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LRegProfile {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub type_str: String,
    #[serde(rename = "type")]
    pub regtype: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LFlagInfo {
    pub offset: u64,
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LBinInfo {
    pub core: Option<LCoreInfo>,
    pub bin: Option<LBin>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LCoreInfo {
    pub file: Option<String>,
    pub size: Option<usize>,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename = "endian")]
pub enum Endian {
    #[serde(rename = "big")]
    Big,
    #[serde(rename = "little")]
    Little,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LBin {
    pub arch: Option<String>,
    pub bits: Option<usize>,
    pub endian: Option<Endian>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub callrefs: Option<Vec<LCallInfo>>,
    pub calltype: Option<String>,
    pub codexrefs: Option<Vec<LCallInfo>>,
    pub datarefs: Option<Vec<u64>>,
    pub dataxrefs: Option<Vec<u64>>,
    pub name: Option<String>,
    pub offset: Option<u64>,
    pub realsz: Option<u64>,
    pub size: Option<u64>,
    #[serde(rename = "type")]
    pub ftype: Option<String>,
    #[serde(skip)]
    pub locals: Option<Vec<LVarInfo>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LCallInfo {
    #[serde(rename = "addr")]
    pub target: Option<u64>,
    #[serde(rename = "type")]
    pub call_type: Option<String>,
    #[serde(rename = "at")]
    pub source: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LSectionInfo {
    pub flags: Option<String>,
    pub name: Option<String>,
    pub paddr: Option<u64>,
    pub size: Option<u64>,
    pub vaddr: Option<u64>,
    pub vsize: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LStringInfo {
    pub length: Option<u64>,
    pub ordinal: Option<u64>,
    pub paddr: Option<u64>,
    pub section: Option<String>,
    pub size: Option<u64>,
    pub string: Option<String>,
    pub vaddr: Option<u64>,
    #[serde(rename = "type")]
    pub stype: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LVarInfo {
    pub name: Option<String>,
    pub kind: Option<String>,
    #[serde(rename = "type")]
    pub vtype: Option<String>,
    #[serde(rename = "ref")]
    pub reference: Option<LVarRef>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LVarRef {
    pub base: Option<String>,
    pub offset: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LCCInfo {
    pub ret: Option<String>,
    pub args: Option<Vec<String>>,
    #[serde(rename = "float_args")]
    pub fargs: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
// Taken from ELF Spec
pub enum LSymbolType {
    Notype,
    Obj,
    Func,
    Section,
    File,
    Common,
    Loos,
    Hios,
    Loproc,
    SparcRegister,
    HiProc,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LSymbolInfo {
    pub demname: Option<String>,
    pub flagname: Option<String>,
    pub name: Option<String>,
    pub paddr: Option<u64>,
    pub size: Option<u64>,
    #[serde(rename = "type")]
    pub stype: Option<LSymbolType>,
    pub vaddr: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
// Taken from ELF Spec
pub enum LBindType {
    Local,
    Global,
    Weak,
    Loos,
    Hios,
    Loproc,
    Hiproc,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LImportInfo {
    pub bind: Option<LBindType>,
    pub name: Option<String>,
    pub ordinal: Option<u64>,
    pub plt: Option<u64>,
    #[serde(rename = "type")]
    pub itype: Option<LSymbolType>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LExportInfo {
    pub demname: Option<String>,
    pub flagname: Option<String>,
    pub name: Option<String>,
    pub paddr: Option<u64>,
    pub size: Option<u64>,
    #[serde(rename = "type")]
    pub etype: Option<LSymbolType>,
    pub vaddr: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LRelocInfo {
    pub is_ifunc: Option<bool>,
    pub name: Option<String>,
    pub paddr: Option<u64>,
    #[serde(rename = "type")]
    // TODO
    pub rtype: Option<String>,
    pub vaddr: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LEntryInfo {
    pub vaddr: Option<u64>,
    pub paddr: Option<u64>,
    pub baddr: Option<u64>,
    pub laddr: Option<u64>,
    pub haddr: Option<u64>,
    pub etype: Option<String>,
}
