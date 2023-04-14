use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::LinkedList;
use std::iter::FromIterator;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Shl, Sub};
use std::process::Command;

use common::{Addr, Register};
use esil::ESILNode;
use log::error;
use log::{trace, warn};
use num_bigint::BigUint;
use num_traits::identities::{One, Zero};
use r2api::api_trait::R2Api;
use r2contrib::{FunctionWithBBs, MemoryMap, BB};
use r2pipe::r2::R2;
use util::find_path;
use registers::RegisterSet;
use tera::{Context, Tera};

pub type DataflowMap = HashMap<Addr, DataflowAnnotation>;
pub type DFRegisterSet = BigUint;
pub type DFRegister = DFRegisterSet;

type InvertedBBNode = Vec<Addr>;
type InvertedBBGraph = HashMap<Addr, InvertedBBNode>;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DataflowChanges {
    pub added_regs: DFRegisterSet,
    pub removed_regs: DFRegisterSet,
    pub copy_flow: HashMap<DFRegister, DFRegisterSet>,
    pub critical_access: DFRegisterSet,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DataflowAnnotation {
    pub state: DFRegisterSet,
    pub state_outgoing: DFRegisterSet,
    pub prev_state: DFRegisterSet,
    pub prev_state_outgoing: DFRegisterSet,
    pub changes: DataflowChanges,
    pub conversion_necessary: bool,
    pub conversions: DFRegisterSet,
}

pub struct DataflowArch {
    pub regs: RegisterSet,
    pub discard_zero_reg: bool,
}

pub type ConversionOrigins = HashMap<Addr, HashMap<DFRegister, HashSet<Addr>>>;

#[derive(Serialize)]
pub struct PathKeyIndicators {
    distance: u64,
}

pub struct PairKeyIndicators {
    paths: Vec<PathKeyIndicators>,
    reg: DFRegister,
    to: Addr,
}

pub struct CriticalInsnKeyIndicators {
    pairs: Vec<PairKeyIndicators>,
    from: Addr,
}

pub struct KeyIndicators {
    critical_insns: Vec<CriticalInsnKeyIndicators>,
}

impl DataflowArch {
    pub fn new(r2: &mut R2) -> Self {
        DataflowArch {
            regs: RegisterSet::new(r2),
            discard_zero_reg: r2.bin_info().unwrap().bin.unwrap().arch.unwrap()
                == "riscv".to_string(),
        }
    }

    pub fn all(&self) -> DFRegisterSet {
        BigUint::one()
            .shl(self.regs.reg_ids.len())
            .sub(BigUint::one())
    }

    pub fn add_to_set(&self, set: &mut DFRegisterSet, register: Register) {
        set.bitor_assign(
            self.regs
                .reg_ids
                .get(&register)
                .expect(&format!(
                    "add_to_set: unknown reg {} inside set {:?}",
                    &register, &self.regs
                ))
                .clone(),
        );
    }

    pub fn remove_from_set(&self, set: &mut DFRegisterSet, register: Register) {
        let reg_id = self.regs.reg_ids[&register].clone();
        let all = self.all();
        set.bitand_assign(all.sub(reg_id));
    }

    pub fn union(set1: &DFRegisterSet, set2: &DFRegisterSet) -> DFRegisterSet {
        set1.bitor(set2)
    }

    pub fn intersection(set1: &DFRegisterSet, set2: &DFRegisterSet) -> DFRegisterSet {
        set1.bitand(set2)
    }

    pub fn set_minus(&self, set1: &DFRegisterSet, set2: &DFRegisterSet) -> DFRegisterSet {
        set1.bitand(self.all().sub(set2))
    }

    pub fn init_set() -> BigUint {
        BigUint::zero()
    }
    // FIXME: Maybe subtrees allow for tainted results (not yet found in any examples)
    fn check_critical(&self, node_rec: &Box<ESILNode>, critical_set: &mut DFRegisterSet) {
        trace!("{:?}", node_rec);
        match &**node_rec {
            ESILNode::BitAnd(access1, access2)
            | ESILNode::BitOr(access1, access2)
            | ESILNode::BitXor(access1, access2)
            | ESILNode::ShiftLeft(access1, access2)
            | ESILNode::ShiftRight(access1, access2)
            | ESILNode::ArithShiftLeft(access1, access2)
            | ESILNode::ArithShiftRight(access1, access2)
            | ESILNode::RotLeft(access1, access2)
            | ESILNode::RotRight(access1, access2)
            | ESILNode::Eq(access1, access2)
            | ESILNode::Less(access1, access2)
            | ESILNode::LessEq(access1, access2)
            | ESILNode::Greater(access1, access2)
            | ESILNode::GreaterEq(access1, access2)
            | ESILNode::BitAndAssign(access1, access2)
            | ESILNode::BitOrAssign(access1, access2)
            | ESILNode::BitXorAssign(access1, access2)
            | ESILNode::ShiftLeftAssign(access1, access2)
            | ESILNode::ShiftRightAssign(access1, access2)
            | ESILNode::AndAssignMem(_, access1, access2)
            | ESILNode::OrAssignMem(_, access1, access2)
            | ESILNode::XorAssignMem(_, access1, access2)
            | ESILNode::ShiftLeftAssignMem(_, access1, access2)
            | ESILNode::ShiftRightAssignMem(_, access1, access2)
            | ESILNode::ArithShiftLeftAssign(access1, access2)
            | ESILNode::ArithShiftRightAssign(access1, access2) => {
                if let ESILNode::Reg(r) = &**access1 {
                    self.add_to_set(critical_set, r.clone());
                } else {
                    self.check_critical(&*access1, critical_set);
                }

                if let ESILNode::Reg(r) = &**access2 {
                    self.add_to_set(critical_set, r.clone());
                } else {
                    self.check_critical(&*access2, critical_set);
                }
            }

            ESILNode::LoadMem(access1)
            | ESILNode::LoadMemSized(_, access1)
            | ESILNode::NotAssign(access1)
            | ESILNode::Not(access1)
            | ESILNode::ConditionalStart(access1)
            | ESILNode::LoadMemMulti(access1, _) => {
                if let ESILNode::Reg(r) = &**access1 {
                    self.add_to_set(critical_set, r.clone());
                } else {
                    self.check_critical(&*access1, critical_set);
                }
            }

            ESILNode::AssignMemMulti(access1, inner) => {
                if let ESILNode::Reg(r) = &**access1 {
                    self.add_to_set(critical_set, r.clone());
                } else {
                    self.check_critical(&*access1, critical_set);
                    // TODO Check for Conditionals
                }
                for i in inner {
                    self.check_critical(i, critical_set);
                }
            }

            ESILNode::ConditionalEnd(access1, inner, inner_else) => {
                self.check_critical(&*access1, critical_set);
                for i in inner {
                    self.check_critical(i, critical_set);
                }
                for i in inner_else {
                    self.check_critical(i, critical_set);
                }
            }

            ESILNode::Add(access1, access2)
            | ESILNode::Sub(access1, access2)
            | ESILNode::Mul(access1, access2)
            | ESILNode::Div(access1, access2)
            | ESILNode::Mod(access1, access2)
            | ESILNode::AddAssign(access1, access2)
            | ESILNode::SubAssign(access1, access2)
            | ESILNode::MulAssign(access1, access2)
            | ESILNode::DivAssign(access1, access2)
            | ESILNode::ModAssign(access1, access2)
            | ESILNode::AddAssignMem(_, access1, access2)
            | ESILNode::SubAssignMem(_, access1, access2)
            | ESILNode::MulAssignMem(_, access1, access2)
            | ESILNode::DivAssignMem(_, access1, access2)
            | ESILNode::Assign(access1, access2)
            | ESILNode::BitAssign(access1, access2)
            | ESILNode::AssignMem(access1, access2)
            | ESILNode::AssignMemSized(_, access1, access2) => {
                self.check_critical(&*access1, critical_set);
                self.check_critical(&*access2, critical_set);
            }

            ESILNode::Inc(access1)
            | ESILNode::Dec(access1)
            | ESILNode::IncAssign(access1)
            | ESILNode::DecAssign(access1)
            | ESILNode::IncAssignMem(_, access1)
            | ESILNode::DecAssignMem(_, access1)
                => {
                self.check_critical(&*access1, critical_set);
            }
            // FIXME Conversion critical?
            _ => {}
        }
    }

    fn get_assignment_taining(
        &self,
        nodes: &Vec<Box<ESILNode>>,
    ) -> (
        DFRegisterSet,
        DFRegisterSet,
        HashMap<DFRegister, DFRegisterSet>,
        DFRegisterSet,
    ) {
        let mut added_regs_vec = Vec::new();
        let mut removed_regs_vec = Vec::new();
        let mut copy_flow_vec = Vec::new();

        for node in nodes {
            match &**node {
                ESILNode::Assign(target, expr) => match &**target {
                    ESILNode::Reg(target_reg) => match &**expr {
                        ESILNode::Reg(reg2) => {
                            copy_flow_vec.push((
                                self.regs
                                    .reg_ids
                                    .get(&reg2.clone())
                                    .expect(&format!("get_assignment_tainting: unknown register {:?} in node {:?}", &reg2, &node))
                                    .clone(),
                                target_reg.clone(),
                            ));
                        }

                        ESILNode::Add(_, _)
                        | ESILNode::Sub(_, _)
                        | ESILNode::Mul(_, _)
                        | ESILNode::Div(_, _)
                        | ESILNode::Mod(_, _)
                        | ESILNode::Inc(_)
                        | ESILNode::Dec(_) => {
                            added_regs_vec.push(target_reg.clone());
                        }

                        ESILNode::BitAnd(_, _)
                        | ESILNode::BitOr(_, _)
                        | ESILNode::BitXor(_, _)
                        | ESILNode::Not(_)
                        | ESILNode::ShiftLeft(_, _)
                        | ESILNode::ShiftRight(_, _)
                        | ESILNode::ArithShiftLeft(_, _)
                        | ESILNode::ArithShiftRight(_, _)
                        | ESILNode::RotLeft(_, _)
                        | ESILNode::RotRight(_, _)
                        | ESILNode::LoadMem(_)
                        | ESILNode::LoadMemSized(_, _)
                        | ESILNode::Imm(_)
                        | ESILNode::Eq(_, _)
                        | ESILNode::Less(_, _)
                        | ESILNode::LessEq(_, _)
                        | ESILNode::Greater(_, _)
                        | ESILNode::GreaterEq(_, _) => {
                            removed_regs_vec.push(target_reg.clone());
                        }

                        _ => (),
                    },
                    ESILNode::Imm(0) => {
                        if !self.discard_zero_reg {
                            error!(
                                "unexpected assign target {:?} in expression {:?}",
                                &target, &node
                            );
                            panic!("unexpected assign target");
                        }
                    }

                    ESILNode::LoadMem(_)
                    | ESILNode::LoadMemSized(_, _)
                    | ESILNode::LoadMemMulti(_, _) => (),

                    _ => {
                        error!("unexpected assign target {:?} in expression {:?}",
                               &target, &node);
                        panic!("unexpected assign target");
                    },
                },
                ESILNode::AddAssign(target, _)
                | ESILNode::SubAssign(target, _)
                | ESILNode::MulAssign(target, _)
                | ESILNode::DivAssign(target, _)
                | ESILNode::ModAssign(target, _)
                | ESILNode::IncAssign(target)
                | ESILNode::DecAssign(target)
                    => match &**target {
                    ESILNode::Reg(target_reg) => {
                        added_regs_vec.push(target_reg.clone());
                    }

                    ESILNode::LoadMem(_)
                    | ESILNode::LoadMemSized(_, _)
                    | ESILNode::LoadMemMulti(_, _) => (),

                    _ => {
                        error!(
                            "unexpected assign target {:?} in expression {:?}",
                            &target, &node
                        );
                        panic!("unexpected assign target")
                    },
                },
                ESILNode::BitAndAssign(target, _)
                | ESILNode::BitOrAssign(target, _)
                | ESILNode::BitXorAssign(target, _)
                | ESILNode::NotAssign(target)
                | ESILNode::ShiftLeftAssign(target, _)
                | ESILNode::ShiftRightAssign(target, _)
                | ESILNode::ArithShiftLeftAssign(target, _)
                | ESILNode::ArithShiftRightAssign(target, _) => match &**target {
                    ESILNode::Reg(target_reg) => {
                        removed_regs_vec.push(target_reg.clone());
                    }

                    ESILNode::LoadMem(_)
                    | ESILNode::LoadMemSized(_, _)
                    | ESILNode::LoadMemMulti(_, _) => (),

                    _ => {
                        error!(
                            "unexpected assign target {:?} in expression {:?}",
                            &target, &node
                        );
                        panic!("unexpected assign target")
                    },
                },
                ESILNode::LoadMemMulti(_, targets) => {
                    for target in targets {
                        match &**target {
                            ESILNode::Reg(target_reg) => {
                                removed_regs_vec.push(target_reg.clone());
                            }

                            ESILNode::LoadMem(_)
                            | ESILNode::LoadMemSized(_, _)
                            | ESILNode::LoadMemMulti(_, _) => (),

                            _ => panic!("non-Reg target(s) in [*]"),
                        }
                    }
                }
                _ => (),
            }
        }

        let mut critical_access = Self::init_set();
        for node in nodes {
            self.check_critical(node, &mut critical_access);
        }

        let mut copy_flow_sets: HashMap<DFRegister, HashSet<Register>> = HashMap::new();
        for (target, expr) in copy_flow_vec {
            if !copy_flow_sets.contains_key(&target) {
                copy_flow_sets.insert(target.clone(), HashSet::new());
            }
            copy_flow_sets.get_mut(&target).unwrap().insert(expr);
        }

        let copy_flow = HashMap::from_iter(copy_flow_sets.into_iter().map(|(target, set)| {
            let df_set = set
                .into_iter()
                .fold(DataflowArch::init_set(), |set, new_element| {
                    let mut new_set = set.clone();
                    self.add_to_set(&mut new_set, new_element);
                    new_set
                });
            (target.clone(), df_set)
        }));

        let added_regs = added_regs_vec
            .into_iter()
            .fold(Self::init_set(), |set, elem| {
                let mut new_set = set.clone();
                self.add_to_set(&mut new_set, elem);
                new_set.clone()
            });

        let removed_regs = removed_regs_vec
            .into_iter()
            .fold(Self::init_set(), |set, elem| {
                let mut new_set = set.clone();
                self.add_to_set(&mut new_set, elem);
                new_set.clone()
            });

        (added_regs, removed_regs, copy_flow, critical_access)
    }

    pub fn calculate_changes(&self, bb: &BB, dataflow_map: &mut DataflowMap) {
        let (added_regs, removed_regs, copy_flow, critical_access) = self.get_assignment_taining(
            &bb.disasm
                .as_ref()
                .unwrap()
                .into_iter()
                .map(|insn| {
                    let esil = insn.esil.as_ref();
                    trace!("Insn/Esil Translation: {:?} -> {:?}", insn.opcode, esil);
                    match esil {
                        Some(some_esil) => ESILNode::from(some_esil),
                        None => {
                            warn!("Warning: no esil found for insn {:?}", &insn);
                            vec![]
                        }
                    }
                })
                .flatten()
                .collect::<Vec<Box<ESILNode>>>(),
        );
        dataflow_map.insert(
            bb.addr,
            DataflowAnnotation {
                state: Self::init_set(),
                state_outgoing: added_regs.clone(),
                prev_state: Self::init_set(),
                prev_state_outgoing: Self::init_set(),
                changes: DataflowChanges {
                    added_regs,
                    removed_regs,
                    copy_flow,
                    critical_access,
                },
                conversion_necessary: false,
                conversions: Self::init_set(),
            },
        );
    }

    pub fn wl_algorithm(&self, fun: &FunctionWithBBs) -> DataflowMap {
        let bbs = &fun.minimal_bbs;
        let mut dataflow_map = DataflowMap::new();

        for bb in bbs.values() {
            self.calculate_changes(bb, &mut dataflow_map);
        }

        let mut wl: LinkedList<&BB> = LinkedList::new();
        for bb in bbs.values() {
            wl.push_back(bb)
        }

        for i in &wl {
            trace!("WL Entry {:08x} {:?}",
                     &i.disasm.to_owned().unwrap()[0].offset.unwrap(),
                     &i.disasm.to_owned().unwrap()[0].opcode,
            );
        }

        let mut iteration: u64 = 0;

        while !wl.is_empty() {
            iteration += 1;

            trace!("Outer Loop Begin");
            for i in &wl {
                trace!("WL Entry {:08x} {:?}",
                         &i.disasm.to_owned().unwrap()[0].offset.unwrap(),
                         &i.disasm.to_owned().unwrap()[0].opcode,
                );
            }

            let bb = wl.pop_back().unwrap();
            let df_bb = dataflow_map[&bb.addr].clone();

            for succ in vec![bb.jump, bb.fail].into_iter().flatten() {
                let succ_struct_opt = &bbs.get(&succ);
                if succ_struct_opt.is_none() {
                    warn!(
                        "Warning: {:x?} of succs jump {:x?} fail {:x?} not found in BB map",
                        &succ, &bb.jump, &bb.fail
                    );
                    continue;
                }
                let succ_struct = succ_struct_opt.unwrap();

                let mut bb_succ = &mut dataflow_map.get_mut(&succ_struct.addr).unwrap();

                bb_succ.prev_state_outgoing = bb_succ.state_outgoing.clone();
                bb_succ.prev_state = bb_succ.state.clone();

                bb_succ.state = Self::union(&bb_succ.state, &df_bb.state_outgoing);
                bb_succ.state_outgoing = self.set_minus(&bb_succ.state, &bb_succ.changes.removed_regs);
                bb_succ.state_outgoing = Self::union(&bb_succ.state_outgoing, &bb_succ.changes.added_regs);

                // FIXME Always do whole sets

                let conversions =
                    Self::intersection(&bb_succ.state, &bb_succ.changes.critical_access);
                bb_succ.conversion_necessary = !conversions.is_zero();
                trace!("{:08x} {:?} Pred {:08x} {:?} State {:016b} StateOut {:016b} Conv {:016b} Crit {:016b}",
                         &succ_struct.disasm.to_owned().unwrap()[0].offset.unwrap(),
                         &succ_struct.disasm.to_owned().unwrap()[0].opcode,
                         &bb.disasm.to_owned().unwrap()[0].offset.unwrap(),
                         &bb.disasm.to_owned().unwrap()[0].opcode,
                         &bb_succ.state, &bb_succ.state_outgoing, &conversions,
                         &bb_succ.changes.critical_access
                );
                bb_succ.conversions = conversions;

                for (r, copy_set) in &bb_succ.changes.copy_flow {
                    if !r.bitand(&df_bb.state_outgoing).is_zero() {
                        bb_succ.state_outgoing = Self::union(&bb_succ.state_outgoing, &copy_set);
                    }
                }

                if bb_succ.prev_state_outgoing != bb_succ.state_outgoing {
                    // wl.push_back(&succ);
                    wl.push_back(&bbs[&succ]);
                //    for succ_succ in vec![succ_struct.jump, succ_struct.fail].into_iter().flatten() {
                //        wl.push_back(&bbs[&succ_succ]);
                //        trace!("Succ to WL: {:?}", &bbs[&succ_succ]);
                //        for i in &wl {
                //            trace!("WL Entry {:08x} {:?}",
                //                     &i.disasm.to_owned().unwrap()[0].offset.unwrap(),
                //                     &i.disasm.to_owned().unwrap()[0].opcode,
                //            );
                //        }
                //    }
                }
                trace!("WL: {:?}", &wl.len());
            }
            trace!("Outer Loop End");
            for i in &wl {
                trace!("WL Entry {:08x} {:?}",
                         &i.disasm.to_owned().unwrap()[0].offset.unwrap(),
                         &i.disasm.to_owned().unwrap()[0].opcode,
                );
            }
        }
        trace!("WL Algorithm iteration took {}", iteration);
        dataflow_map
    }

    fn inverted_bbs(fun: &FunctionWithBBs) -> InvertedBBGraph {
        let mut result = InvertedBBGraph::new();
        for (addr, _) in &fun.minimal_bbs {
            result.insert(*addr, Vec::new());
        }

        for (addr, bb) in &fun.minimal_bbs {
            for succ in vec![bb.jump, bb.fail] {
                if succ.is_some() {
                    let mut inputs = result.get_mut(&succ.unwrap());
                    if inputs.is_some() {
                        inputs.as_mut().unwrap().push(*addr);
                    }
                }
            }
        }

        result
    }

    pub fn backtrack(&self, fun: &FunctionWithBBs, dfm: &DataflowMap) -> ConversionOrigins {
        let inverted = Self::inverted_bbs(fun);
        let mut result = ConversionOrigins::new();

        for (addr, _) in dfm {
            result.insert(*addr, HashMap::new());
        }

        for (addr, dfa) in dfm {
            for r in self.regs.reg_ids.values() {
                if !r.bitand(&dfa.conversions).is_zero() {
                    // DFS till tainting
                    let mut current = addr;
                    let mut history = HashSet::new();
                    let mut backlog = Vec::new();

                    history.insert(current);
                    for pred in inverted.get(current).as_ref().unwrap().into_iter() {
                        backlog.push(pred)
                    }

                    while !backlog.is_empty() {
                        current = backlog.pop().unwrap();

                        let added = !dfm[current].changes.added_regs.clone().bitand(r).is_zero();
                        let copied = dfm[current].changes.copy_flow.iter().map(
                            |(_from, copy_set)| {
                                !copy_set.bitand(r).is_zero()
                            }).fold(false, bool::bitand);

                        if added || copied {
                            if !result[addr].contains_key(r) {
                                result
                                    .get_mut(addr)
                                    .unwrap()
                                    .insert((*r).clone(), HashSet::new());
                            }

                            result
                                .get_mut(addr)
                                .unwrap()
                                .get_mut(r)
                                .unwrap()
                                .insert(*current);
                        } else {
                            if !dfm[current].changes.removed_regs.clone().bitand(r).is_zero() {
                                continue;
                            }
                            for pred in inverted.get(current).as_ref().unwrap().into_iter() {
                                if !history.contains(&pred) {
                                    history.insert(&pred);
                                    backlog.push(&pred);
                                }
                            }
                        }
                    }
                }
            }
        }

        result
    }

    pub fn get_key_indicators(
        &self,
        fun: &FunctionWithBBs,
        dfm: &DataflowMap,
        co: &ConversionOrigins,
    ) -> KeyIndicators {
        let inverted = Self::inverted_bbs(fun); // TODO cache inverted

        let mut critical_insns = Vec::new();

        for (from_addr, reg_addr_map) in co {
            let mut pairs = Vec::new();

            for (reg, addr_set) in reg_addr_map {
                for to_addr in addr_set {
                    let mut paths = Vec::new();

                    if !dfm[from_addr]
                        .changes
                        .added_regs
                        .clone()
                        .bitand(reg)
                        .is_zero()
                    {
                        paths.push(PathKeyIndicators { distance: 0 })
                    } else {
                        let mut backlog = Vec::new();
                        let mut history = HashSet::new();
                        history.insert(from_addr);
                        backlog.push((1, history, from_addr));

                        while !backlog.is_empty() {
                            let (distance, history, current) = backlog.pop().unwrap();

                            if !dfm[current]
                                .changes
                                .added_regs
                                .clone()
                                .bitand(reg)
                                .is_zero()
                            {
                                paths.push(PathKeyIndicators { distance });
                            } else {
                                for pred in inverted.get(current).as_ref().unwrap().into_iter() {
                                    if let Some(df_pred) = dfm.get(pred) {
                                        if !df_pred
                                            .changes
                                            .removed_regs
                                            .clone()
                                            .bitand(reg)
                                            .is_zero()
                                        {
                                            continue;
                                        }
                                    }
                                    if !history.contains(&pred) {
                                        let mut new_history = history.clone();
                                        new_history.insert(&pred);
                                        backlog.push((distance + 1, new_history, &pred));
                                    }
                                }
                            }
                        }
                    }

                    if !paths.is_empty() {
                        pairs.push(PairKeyIndicators {
                            paths,
                            reg: reg.clone(),
                            to: to_addr.clone(),
                        });
                    }
                }
            }

            if !pairs.is_empty() {
                critical_insns.push(CriticalInsnKeyIndicators {
                    pairs,
                    from: from_addr.clone(),
                });
            }
        }

        KeyIndicators {
            critical_insns,
        }
    }

    pub fn gen_cytoscape(
        &self,
        fun: &FunctionWithBBs,
        dfm: &DataflowMap,
        filename: &String,
        memory_map: &MemoryMap,
        conversion_origins: Option<ConversionOrigins>,
        key_indicators: Option<KeyIndicators>,
        footer: &Option<String>
    ) -> String {
        #[derive(Serialize)]
        struct Node {
            pub id: String,
            pub label: String,
            pub color: String,
        }
        #[derive(Serialize)]
        struct NodeWrapper {
            pub data: Node,
        }
        #[derive(Serialize)]
        struct Edge {
            pub id: String,
            pub source: String,
            pub target: String,
            pub color: String,
        }
        #[derive(Serialize)]
        struct EdgeWrapper {
            pub data: Edge,
        }
        #[derive(Serialize)]
        struct Graph {
            pub nodes: Vec<NodeWrapper>,
            pub edges: Vec<EdgeWrapper>,
        }

        let bbs = &fun.minimal_bbs;

        let nodes = bbs
            .into_iter()
            .map(|(_, bb)| {
                let op_str = bb
                    .disasm
                    .as_ref()
                    .unwrap()
                    .into_iter()
                    .map(|op| {
                        op.opcode
                            .as_ref()
                            .unwrap_or(&"no opcode".to_string())
                            .clone()
                    })
                    .collect::<Vec<String>>()
                    .join("|");
                let label = format!("{}", &op_str);
                let id = bb.addr;

                let color = if (&dfm[&bb.addr]).conversion_necessary {
                    "lightcoral"
                } else {
                    "lightgrey"
                }
                .to_string();

                NodeWrapper {
                    data: Node {
                        id: format!("{}", id),
                        label,
                        color,
                    },
                }
            })
            .chain(vec![NodeWrapper {
                data: Node {
                    id: "exit".to_string(),
                    label: "EXIT NODE".to_string(),
                    color: "black".to_string(),
                },
            }])
            .collect::<Vec<NodeWrapper>>();

        let edges = bbs
            .into_iter()
            .map(|(_, bb)| {
                let jump = bb.jump.map(|link| EdgeWrapper {
                    data: Edge {
                        id: format!("{}_{}", bb.addr, link),
                        source: format!("{}", bb.addr),
                        target: format!("{}", link),
                        color: "darkgreen".to_string(),
                    },
                });
                let fail = bb.fail.map(|link| EdgeWrapper {
                    data: Edge {
                        id: format!("{}_{}", bb.addr, link),
                        source: format!("{}", bb.addr),
                        target: format!("{}", link),
                        color: "darkred".to_string(),
                    },
                });
                let exit = if bb.jump.is_none() && bb.fail.is_none() {
                    Some(EdgeWrapper {
                        data: Edge {
                            id: format!("{}_exit", bb.addr),
                            source: format!("{}", bb.addr),
                            target: "exit".to_string(),
                            color: "pink".to_string(),
                        },
                    })
                } else {
                    None
                };
                vec![jump, fail, exit].into_iter().flatten()
            })
            .flatten()
            .collect::<Vec<EdgeWrapper>>();

        let graph = Graph {
            nodes,
            edges,
        };

        #[derive(Serialize)]
        struct DataflowDescription {
            pub state: Vec<Register>,
            pub state_outgoing: Vec<Register>,
            pub added_regs: Vec<Register>,
            pub removed_regs: Vec<Register>,
            pub copy_flow: HashMap<Register, Vec<Register>>,
            pub conversions: Vec<Register>,
            pub line: String,
        }

        let dfm_mod: HashMap<String, DataflowDescription> =
            HashMap::from_iter(dfm.into_iter().map(|(addr, df)| {
                let state_set = &df.state.clone();
                let state_outgoing_set = &df.state_outgoing.clone();
                let added_set = &df.changes.added_regs.clone();
                let removed_set = &df.changes.removed_regs.clone();
                let conversions_set = &df.changes.critical_access.clone();
                let copy_set = &df.changes.copy_flow.clone();

                let r = self.regs.reg_ids.clone();

                let mut state = Vec::new();
                let mut state_outgoing = Vec::new();
                let mut added = Vec::new();
                let mut conversions = Vec::new();
                let mut removed = Vec::new();
                let mut copy = HashMap::new();

                for (name, id) in &r {
                    if !state_set.bitand(id.clone()).is_zero() {
                        state.push(name.clone());
                    }
                    if !state_outgoing_set.bitand(id.clone()).is_zero() {
                        state_outgoing.push(name.clone());
                    }
                    if !added_set.bitand(id.clone()).is_zero() {
                        added.push(name.clone());
                    }
                    if !removed_set.bitand(id.clone()).is_zero() {
                        removed.push(name.clone());
                    }
                    if !conversions_set.bitand(id.clone()).is_zero() {
                        conversions.push(name.clone());
                    }
                }

                for (copy_from, copy_target_set) in copy_set {
                    let mut copy_name = None;
                    let mut copy_target_set_string = Vec::new();
                    for (name, id) in &r {
                        if copy_from.clone() == id.clone() {
                            copy_name = Some(name.clone());
                        }
                        if !copy_target_set.bitand(id.clone()).is_zero() {
                            copy_target_set_string.push(name.clone());
                        }
                    }
                    copy_target_set_string.sort();
                    copy.insert(copy_name.unwrap(), copy_target_set_string);
                }

                state.sort();
                state_outgoing.sort();

                let norm_addr = (|| {
                    for mm in memory_map {
                        if addr > &mm.from && addr <= &mm.to {
                            return addr - mm.from;
                        }
                    }
                    *addr
                })();

                let line = String::from_utf8(
                    Command::new("addr2line")
                        .args(&[
                            "-f",
                            "-s",
                            "-e",
                            filename,
                            format!("+0x{:x}", &norm_addr).as_str(),
                        ])
                        .output()
                        .expect("failed to execute addr2line")
                        .stdout,
                )
                .expect("couldn't parse output from addr2line");

                let dfd = DataflowDescription {
                    state,
                    state_outgoing,
                    added_regs: added,
                    removed_regs: removed,
                    copy_flow: copy,
                    conversions,
                    line,
                };

                (format!("{}", addr).to_string(), dfd)
            }));

        let conv = conversion_origins.map(|c| {
            c.into_iter()
                .map(|(addr, v)| {
                    (
                        format!("{}", addr),
                        v.into_iter()
                            .map(|(reg, origin)| {
                                let r = self.regs.reg_ids.clone();
                                (
                                    r.into_iter()
                                        .map(|(name, id)| {
                                            if !id.bitand(reg.clone()).is_zero() {
                                                Some(name)
                                            } else {
                                                None
                                            }
                                        })
                                        .flatten()
                                        .last()
                                        .unwrap(),
                                    origin
                                        .into_iter()
                                        .map(|x| format!("{}", x))
                                        .collect::<Vec<String>>(),
                                )
                            })
                            .collect::<HashMap<String, Vec<String>>>(),
                    )
                })
                .collect::<HashMap<String, HashMap<String, Vec<String>>>>()
        });

        #[derive(Serialize)]
        pub struct PairKeyIndicatorsJSON {
            paths: Vec<PathKeyIndicators>,
            reg: Register,
            to: Addr,
        }

        #[derive(Serialize)]
        pub struct CriticalInsnKeyIndicatorsJSON {
            pairs: Vec<PairKeyIndicatorsJSON>,
            from: Addr,
        }

        #[derive(Serialize)]
        pub struct KeyIndicatorsJSON {
            critical_insns: Vec<CriticalInsnKeyIndicatorsJSON>,
        }

        let indicators = key_indicators.map(|k| KeyIndicatorsJSON {
            critical_insns: k
                .critical_insns
                .into_iter()
                .map(|c_insn| CriticalInsnKeyIndicatorsJSON {
                    pairs: c_insn
                        .pairs
                        .into_iter()
                        .map(|pair| {
                            let r = self.regs.reg_ids.clone();
                            let reg = r
                                .into_iter()
                                .map(|(name, id)| {
                                    if !id.bitand(pair.reg.clone()).is_zero() {
                                        Some(name)
                                    } else {
                                        None
                                    }
                                })
                                .flatten()
                                .last()
                                .unwrap();

                            PairKeyIndicatorsJSON {
                                paths: pair.paths,
                                reg: reg.clone(),
                                to: pair.to.clone(),
                            }
                        })
                        .collect(),
                    from: c_insn.from.clone(),
                })
                .collect(),
        });


        let template_path = find_path(
            "TEMPLATE_DIR".to_string(),
            "../../src/templates/".to_string(),
            "index.html".to_string())
            .expect("couldn't find template dir").join("*");

        let tera = Tera::new(template_path.to_str().unwrap())
            .expect("cannot compile template");

        let mut ctx = Context::new();
        ctx.insert("graph", &serde_json::to_string(&graph).unwrap());
        ctx.insert("name", &fun.function.name);

        if let Some(footer_content) = footer {
            ctx.insert("footer", &footer_content);
        } else {
            ctx.insert("footer", "");
        }

        let mut registers = self
            .regs
            .reg_ids
            .keys()
            .map(|x| x.clone())
            .collect::<Vec<String>>();
        registers.sort();
        ctx.insert("registers", &registers);
        ctx.insert("dfm", &serde_json::to_string(&dfm_mod).unwrap());
        let disasm: HashMap<String, String> =
            HashMap::from_iter(bbs.into_iter().map(|(addr, bb)| {
                let op_str = bb
                    .disasm
                    .as_ref()
                    .unwrap()
                    .into_iter()
                    .map(|op| {
                        op.opcode
                            .as_ref()
                            .unwrap_or(&"no opcode".to_string())
                            .clone()
                    })
                    .collect::<Vec<String>>()
                    .join(" | ");
                (format!("{}", addr), op_str)
            }));
        ctx.insert("disasm", &serde_json::to_string(&disasm).unwrap());
        let esil: HashMap<String, String> =
            HashMap::from_iter(bbs.into_iter().map(|(addr, bb)| {
                let op_str = bb
                    .disasm
                    .as_ref()
                    .unwrap()
                    .into_iter()
                    .map(|op| {
                        op.esil
                            .as_ref()
                            .unwrap_or(&"no esil".to_string())
                            .clone()
                            .replace(",", ", ")
                    })
                    .collect::<Vec<String>>()
                    .join(" | ");
                (format!("{}", addr), op_str)
            }));
        ctx.insert("esil", &serde_json::to_string(&esil).unwrap());
        ctx.insert("conv", &serde_json::to_string(&conv).unwrap());
        ctx.insert("indicators", &serde_json::to_string(&indicators).unwrap());
        ctx.insert("metrics", &indicators.is_some());

        tera.render("cytoscape.html", &ctx).unwrap()
    }
}
