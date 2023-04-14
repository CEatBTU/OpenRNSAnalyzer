use std::collections::HashMap;
use std::iter::FromIterator;

use r2api::api_trait::R2Api;
use r2api::structs::*;
use r2pipe::r2::R2;
use serde_json::{from_str, Error};

use common::Addr;
use r2structs::RegisterProfile;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BB {
    pub addr: Addr,

    pub fail: Option<Addr>,
    pub jump: Option<Addr>,

    pub size: Addr,
    pub ninstr: u64,

    pub inputs: Option<u64>,
    pub outputs: u64,

    pub disasm: Option<Vec<LOpInfo>>,
}

pub trait DisasmR2Entity {
    fn disassemble(&mut self, r2: &mut R2);
}

impl DisasmR2Entity for BB {
    fn disassemble(&mut self, r2: &mut R2) {
        self.disasm = Some(
            // r2.disassemble_n_bytes(self.size, Some(self.addr))
            r2.disassemble_n_insts(self.ninstr, Some(self.addr))
                .unwrap_or(vec![]),
        )
    }
}

pub trait SeekableR2Entity {
    fn seek(&self, r2: &mut R2);
}

impl SeekableR2Entity for BB {
    fn seek(&self, r2: &mut R2) {
        r2.seek(self.addr);
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MemoryMapEntries {
    pub map: u64,
    pub fd: u64,
    pub delta: u64,
    pub from: u64,
    pub to: u64,
    pub perm: String,
    pub name: String,
}

pub type MemoryMap = Vec<MemoryMapEntries>;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CoreInfo {
    #[serde(rename="type")]
    pub file_type: String,
    pub file: String,
    pub fd: u64,
    pub size: u64,
    pub humansz: String,
    pub iorw: bool,
    pub mode: String,
    pub obsz: Option<u64>,
    pub block: u64,
    pub format: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BinInfo {
    pub arch: String,
    pub baddr: Addr,
    pub binsz: u64,
    pub bintype: String,
    pub bits: u64,
    pub canary: bool,
    pub class: String,
    pub compiled: String,
    pub compiler: String,
    pub crypto: bool,
    pub dbg_file: String,
    pub endian: String,
    pub havecode: bool,
    pub guid: String,
    pub intrp: String,
    pub laddr: Addr,
    pub lang: String,
    pub linenum: bool,
    pub lsyms: bool,
    pub machine: String,
    pub maxopsz: Option<u64>,
    pub minopsz: Option<u64>,
    pub nx: bool,
    pub os: String,
    pub pcalign: Option<u64>,
    pub pic: bool,
    pub relocs: bool,
    pub rpath: String,
    pub sanitiz: Option<bool>,
    #[serde(rename="static")]
    pub is_static: bool,
    pub stripped: bool,
    pub subsys: String,
    pub va: bool,
    pub checksums: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Info {
    pub core: CoreInfo,
    pub bin: BinInfo,
}

pub trait R2ApiContrib {
    fn bbs<T: AsRef<str>>(&mut self, func: T) -> Result<Vec<BB>, Error>;
    fn seek(&mut self, location: Addr);
    fn register_profile(&mut self) -> Result<RegisterProfile, Error>;
    fn debug_run(&mut self) -> ();
    fn debug_continue(&mut self) -> ();
    fn debug_set_bp(&mut self, location: Addr) -> ();
    fn get_memory_map(&mut self) -> Result<Vec<MemoryMapEntries>, Error>;
    fn info(&mut self) -> Result<Info, Error>;
    fn add_function(&mut self, name: String, location: Addr) -> ();
}

impl R2ApiContrib for R2 {
    fn bbs<T: AsRef<str>>(&mut self, func: T) -> Result<Vec<BB>, Error> {
        let func_name = func.as_ref();
        let cmd = format!("afbj {}", func_name);

        let _ = self.send(&cmd);
        let raw_json = self.recv();
        from_str(&raw_json)
    }

    fn seek(&mut self, location: Addr) {
        let cmd = format!("s {}", location);
        let _ = self.send(&cmd);

        self.recv();
    }

    fn register_profile(&mut self) -> Result<RegisterProfile, Error> {
        let _ = self.send(&format!("drpj"));
        let raw_json = self.recv();
        from_str(&raw_json)
    }

    fn debug_run(&mut self) -> () {
        let _ = self.send(&format!("doo"));
        self.recv();
    }
    fn debug_continue(&mut self) -> () {
        let _ = self.send(&format!("dc"));
        self.recv();
    }
    fn debug_set_bp(&mut self, location: Addr) -> () {
        let _ = self.send(&format!("db {}", location));
        self.recv();
    }

    fn get_memory_map(&mut self) -> Result<MemoryMap, Error> {
        let _ = self.send(&format!("omj"));
        let raw_json = self.recv();
        from_str(&raw_json)
    }

    fn info(&mut self) -> Result<Info, Error> {
        let _ = self.send(&format!("ij"));
        let raw_json = self.recv();
        from_str(&raw_json)
    }

    fn add_function(&mut self, name: String, location: Addr) -> () {
        let _ = self.send(&format!("af x.{} {}", name, location));
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FunctionWithBBs {
    pub function: FunctionInfo,
    pub bbs: HashMap<Addr, BB>,
    pub minimal_bbs: HashMap<Addr, BB>,
}

impl FunctionWithBBs {
    pub fn new(r2: &mut R2, mut function: FunctionInfo) -> Self {
        let name = function.name.as_ref().unwrap();

        function.callrefs = None;
        function.datarefs = None;
        function.codexrefs = None;

        let mut bbs = HashMap::from_iter(r2.bbs(name).unwrap().into_iter().map(|bb| (bb.addr, bb)));

        for bb in &mut bbs.values_mut() {
            bb.disassemble(r2);
        }

        let mut minimal_bbs = HashMap::new();

        for (_addr, bb) in &bbs {
            let disasm = bb.disasm.as_ref().unwrap();
            // let ninstr = &bb.ninstr.clone();
            let bb_size = bb.size.clone();
            let mut cur_size = 0;

            for (_idx, instr) in disasm.into_iter().enumerate() {
                let mut outputs = 0;

                let size: u64 = instr.bytes.as_ref().map_or(instr.size.unwrap(), |bytes| {(bytes.len() / 2) as u64});

                cur_size += size;

                let fail = if cur_size == bb_size {
                    if bb.fail.is_some() {
                        outputs += 1;
                    }
                    bb.fail.clone()
                } else {
                    Some(instr.offset.unwrap().clone() + size)
                };

                let jump = if cur_size == bb_size {
                    if bb.jump.is_some() {
                        outputs += 1;
                    }
                    bb.jump.clone()
                } else {
                    None
                };

                minimal_bbs.insert(
                    instr.offset.unwrap().clone(),
                    BB {
                        addr: instr.offset.unwrap().clone(),

                        fail,
                        jump,
                        size,
                        ninstr: 1,

                        // TODO add inputs
                        inputs: None,
                        outputs,

                        disasm: Some(vec![instr.clone()]),
                    },
                );

                if cur_size == bb_size {
                    break;
                }
            }
        }

        FunctionWithBBs {
            function,
            bbs,
            minimal_bbs,
        }
    }

    pub fn gen_label(ops: &Vec<LOpInfo>) -> String {
        let op_str = ops
            .into_iter()
            .map(|op| {
                op.opcode
                    .as_ref()
                    .unwrap_or(&"no opcode".to_string())
                    .clone()
            })
            .collect::<Vec<String>>()
            .join("|");
        format!("{{{}}}", &op_str)
    }

    fn dot_for_bb_vec(bbs: &Vec<&BB>, init_addr: &Addr) -> String {
        let nodes = bbs
            .into_iter()
            .map(|bb| {
                let label = Self::gen_label(&bb.disasm.as_ref().unwrap().clone());
                format!("\tnode__{}[shape=record, label=\"{}\"];\n", bb.addr, label)
            })
            .collect::<Vec<String>>()
            .join("\n");
        let exit_node = &"\texit_node[shape=doublecircle];".to_string();
        let init_node = format!(
            "\tinit_node[shape=circle];\n\tinit_node -> node__{}\n",
            init_addr
        );
        let edges = bbs
            .into_iter()
            .map(|bb| {
                let mut edge_str = "".to_string();
                if bb.jump.is_some() {
                    edge_str.push_str(
                        format!(
                            "\tnode__{} -> node__{} [color=green]\n",
                            bb.addr,
                            bb.jump.unwrap()
                        )
                        .as_ref(),
                    )
                }
                if bb.fail.is_some() {
                    edge_str.push_str(
                        format!(
                            "\tnode__{} -> node__{} [color=red]\n",
                            bb.addr,
                            bb.fail.unwrap()
                        )
                        .as_ref(),
                    )
                }

                if bb.jump.is_none() && bb.fail.is_none() {
                    edge_str.push_str(format!("\tnode__{} -> exit_node\n", bb.addr).as_ref())
                }
                edge_str
            })
            .collect::<Vec<String>>()
            .join("\n");
        format!(
            "digraph {{\n{}\n{}\n{}\n{}\n}}",
            exit_node, init_node, nodes, edges
        )
    }

    pub fn dot_bbs(&self) -> String {
        Self::dot_for_bb_vec(
            &self.bbs.values().collect::<Vec<&BB>>(),
            &self.function.offset.unwrap(),
        )
    }
    pub fn dot_min_bbs(&self) -> String {
        Self::dot_for_bb_vec(
            &self.minimal_bbs.values().collect::<Vec<&BB>>(),
            &self.function.offset.unwrap(),
        )
    }
}
