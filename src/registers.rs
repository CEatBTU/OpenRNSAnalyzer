use std::collections::HashMap;
use std::collections::HashSet;
use std::iter::FromIterator;

use log::warn;

use r2pipe::r2::R2;
use num_bigint::BigUint;

use common::{Register};
use r2contrib::R2ApiContrib;
use r2structs::RegInfo;

#[derive(Debug, Serialize, PartialEq)]
pub enum RegType {
    GeneralPurpose,
    Flag,
    Debug,
    FPU,
    Segment,
    Vector(u64),
    Other,
}

use std::str::FromStr;

impl FromStr for RegType {
    type Err = ();

    fn from_str(s: &str) -> Result<RegType, ()> {
        match s {
            "gpr" => Ok(RegType::GeneralPurpose),
            "flg" => Ok(RegType::Flag),

            "drx" => Ok(RegType::Debug),
            "seg" => Ok(RegType::Segment),

            "fpu" => Ok(RegType::FPU),

            "xmm" => Ok(RegType::Vector(0)),
            "ymm" => Ok(RegType::Vector(0)),
            "mmx" => Ok(RegType::Vector(0)),
            "vec64" => Ok(RegType::Vector(64)),
            "vec128" => Ok(RegType::Vector(128)),
            "vec256" => Ok(RegType::Vector(256)),
            "vec512" => Ok(RegType::Vector(512)),
            "other" => Ok(RegType::Other),
            _     => { warn!("Could not resolve reg type {:?}", s); Err(()) },
        }

    }
}

pub type RegHierarchy = HashMap<Register, BigUint>;
pub type RegHierarchyNamed = HashMap<Register, HashSet<Register>>;

#[derive(Debug, Serialize)]
pub struct RegisterSet {
    pub reg_hierarchy: RegHierarchy,
    pub reg_hierarchy_named: RegHierarchyNamed,
    pub reg_ids: HashMap<Register, BigUint>,
    pub reg_types: HashMap<Register, RegType>,
}


impl RegisterSet {
    fn get_patches(r2: &mut R2) -> Vec<RegInfo> {
        let info = r2.info().unwrap().bin;
        let rp = r2.register_profile().unwrap().reg_info;
        let bits = info.bits;

        match &info.arch[..] {
            "mips" =>
                (0..32).map(|n| {
                    RegInfo {
                        name: format!("f{}", n),
                        offset: (bits / 8) * n +
                            rp.last().unwrap().offset +
                            rp.last().unwrap().size / 8,
                        size: 64 / 8,
                        regtype: 0,
                        type_str: "fpu".to_string()
                    }
                }).collect(),
            "ppc" =>
                (0..32).map(|n| {
                    RegInfo {
                        name: format!("f{}", n),
                        offset: (bits / 8) * n +
                            rp.last().unwrap().offset +
                            rp.last().unwrap().size / 8,
                        size: 64 / 8,
                        regtype: 0,
                        type_str: "fpu".to_string()
                    }
                }).collect(),
            "arm" => vec![
                RegInfo {
                    name: "nzcv".to_string(),
                    offset:
                        rp.last().unwrap().offset +
                        (rp.last().unwrap().size / 8),
                    size: 64 / 8,
                    regtype: 0,
                    type_str: "flg".to_string()
                },
                RegInfo {
                    name: "ffr".to_string(),
                    offset:
                        rp.last().unwrap().offset +
                        (rp.last().unwrap().size / 8) + 8,
                    size: 64 / 8,
                    regtype: 0,
                    type_str: "other".to_string()
                }
            ],
            "riscv" => vec![
                RegInfo {
                    name: "fflags".to_string(),
                    offset:
                    rp.last().unwrap().offset +
                        (rp.last().unwrap().size / 8),
                    size: 64 / 8,
                    regtype: 0,
                    type_str: "flg".to_string()
                },
                RegInfo {
                    name: "frm".to_string(),
                    offset:
                    rp.last().unwrap().offset +
                        (rp.last().unwrap().size / 8) + 8,
                    size: 64 / 8,
                    regtype: 0,
                    type_str: "other".to_string()
                },
                RegInfo {
                    name: "fcsr".to_string(),
                    offset:
                    rp.last().unwrap().offset +
                        (rp.last().unwrap().size / 8),
                    size: 128 / 8,
                    regtype: 0,
                    type_str: "other".to_string()
                },
                RegInfo {
                    name: "cycle".to_string(),
                    offset:
                    rp.last().unwrap().offset +
                        (rp.last().unwrap().size / 8) + 16,
                    size: 64 / 8,
                    regtype: 0,
                    type_str: "other".to_string()
                },
                RegInfo {
                    name: "time".to_string(),
                    offset:
                    rp.last().unwrap().offset +
                        (rp.last().unwrap().size / 8) + 24,
                    size: 64 / 8,
                    regtype: 0,
                    type_str: "other".to_string()
                },
                RegInfo {
                    name: "instret".to_string(),
                    offset:
                    rp.last().unwrap().offset +
                        (rp.last().unwrap().size / 8) + 32,
                    size: 64 / 8,
                    regtype: 0,
                    type_str: "other".to_string()
                },
                RegInfo {
                    name: "instreth".to_string(),
                    offset:
                    rp.last().unwrap().offset +
                        (rp.last().unwrap().size / 8) + 32 + 4,
                    size: 32 / 8,
                    regtype: 0,
                    type_str: "other".to_string()
                },
                RegInfo {
                    name: "timeh".to_string(),
                    offset:
                    rp.last().unwrap().offset +
                        (rp.last().unwrap().size / 8) + 24 + 4,
                    size: 32 / 8,
                    regtype: 0,
                    type_str: "other".to_string()
                },
                RegInfo {
                    name: "cycleh".to_string(),
                    offset:
                    rp.last().unwrap().offset +
                        (rp.last().unwrap().size / 8) + 16 + 4,
                    size: 32 / 8,
                    regtype: 0,
                    type_str: "other".to_string()
                },
            ],
            _ => Vec::new()
        }
    }
    pub fn new(r2: &mut R2) -> RegisterSet {
        // Step 1: Get RegisterProfile
        let mut rp = r2.register_profile().unwrap().reg_info;
        let mut patches = RegisterSet::get_patches(r2);
        rp.append(&mut patches);

        let reg_ids = HashMap::from_iter(rp.clone().into_iter().enumerate().map(
            |(i, reg)| -> (String, BigUint) {
                (reg.name.clone(), BigUint::from(1 as u64) << i)
            }
        ).into_iter());

        let reg_types = HashMap::from_iter(rp.clone().into_iter().map(
            |reg| -> (String, RegType) {
                (reg.name.clone(), RegType::from_str(&reg.type_str).unwrap())
            }
        ).into_iter());

        // Step 2: Build "Hierarchy"
        let reg_hierarchy_named = RegHierarchyNamed::from_iter(
            rp.clone().into_iter().map(
                |register| -> (Register, HashSet<Register>) {
                    let name = register.name.clone();

                    let set = HashSet::from_iter(rp.clone().into_iter().map(
                        |other_register| {
                            let left_reg        = register.offset.clone() as u128;
                            let right_reg       = register.offset.clone() as u128 + register.size.clone() as u128;
                            let left_other_reg  = other_register.offset.clone() as u128;
                            let right_other_reg = other_register.offset.clone() as u128 + other_register.size.clone() as u128;

                            if (reg_types[&register.name] == reg_types[&other_register.name])  &&
                                ((( &left_reg >=  &left_other_reg) && (  left_reg <   right_other_reg)) ||
                                 ((&right_reg <= &right_other_reg) && (&right_reg >  &left_other_reg)) ||
                                 (( &left_reg <=  &left_other_reg) && (&right_reg >= &right_other_reg))) {
                                    Some(other_register.name.clone())
                                } else {
                                    None
                                }
                        }).flatten());

                    (name, set)
                }
            )
        );

        let reg_hierarchy = RegHierarchy::from_iter(
            reg_hierarchy_named.clone().into_iter().map(
                |(register, set)| {
                    let bitset = set.into_iter().map(
                        |item| { reg_ids[&item].clone() }
                    ).fold(
                        BigUint::from(0 as u64),
                        core::ops::BitOr::bitor
                    );

                    (register, bitset)
                }
            ).collect::<Vec<(Register, BigUint)>>().clone()
        );

        RegisterSet {
            reg_hierarchy,
            reg_hierarchy_named,
            reg_ids,
            reg_types,
        }
    }

    pub fn output_dot(&self) -> String {
        let nodes = self.reg_ids.clone().into_iter().map(
            |(id, _)| { format!("{};", id) }
        ).collect::<Vec<String>>().join("\n");
        let edges = self.reg_hierarchy_named.clone().into_iter().map(
            |(register, set)| {
                set.into_iter().map(
                    |other_register| {
                        format!("{} -> {};", &register.to_string(), &other_register.to_string())
                    }
                ).collect::<Vec<String>>().join("\n")
            }
        ).collect::<Vec<String>>().join("\n");

        format!("digraph {{\n {}\n {}\n }}\n", &nodes, &edges)
    }
}
