use std::i128;

use pest::iterators::Pair;
use pest::Parser;

use log::{warn,trace};

#[derive(Clone, Debug)]
pub enum ESILNode {
    Imm(i128),
    Reg(String),
    Flag(String),

    Add(Box<ESILNode>, Box<ESILNode>),
    Sub(Box<ESILNode>, Box<ESILNode>),
    Mul(Box<ESILNode>, Box<ESILNode>),
    Div(Box<ESILNode>, Box<ESILNode>),
    Mod(Box<ESILNode>, Box<ESILNode>),

    Inc(Box<ESILNode>),
    Dec(Box<ESILNode>),

    ShiftLeft(Box<ESILNode>, Box<ESILNode>),
    ShiftRight(Box<ESILNode>, Box<ESILNode>),
    ArithShiftLeft(Box<ESILNode>, Box<ESILNode>),
    ArithShiftRight(Box<ESILNode>, Box<ESILNode>),
    RotLeft(Box<ESILNode>, Box<ESILNode>),
    RotRight(Box<ESILNode>, Box<ESILNode>),

    BitAnd(Box<ESILNode>, Box<ESILNode>),
    BitOr(Box<ESILNode>, Box<ESILNode>),
    BitXor(Box<ESILNode>, Box<ESILNode>),
    Not(Box<ESILNode>),

    AddAssign(Box<ESILNode>, Box<ESILNode>),
    SubAssign(Box<ESILNode>, Box<ESILNode>),
    MulAssign(Box<ESILNode>, Box<ESILNode>),
    DivAssign(Box<ESILNode>, Box<ESILNode>),
    ModAssign(Box<ESILNode>, Box<ESILNode>),

    IncAssign(Box<ESILNode>),
    DecAssign(Box<ESILNode>),

    ShiftLeftAssign(Box<ESILNode>, Box<ESILNode>),
    ShiftRightAssign(Box<ESILNode>, Box<ESILNode>),
    ArithShiftLeftAssign(Box<ESILNode>, Box<ESILNode>),
    ArithShiftRightAssign(Box<ESILNode>, Box<ESILNode>),

    AddAssignMem(u64, Box<ESILNode>, Box<ESILNode>),
    SubAssignMem(u64, Box<ESILNode>, Box<ESILNode>),
    MulAssignMem(u64, Box<ESILNode>, Box<ESILNode>),
    DivAssignMem(u64, Box<ESILNode>, Box<ESILNode>),
    ModAssignMem(u64, Box<ESILNode>, Box<ESILNode>),

    AndAssignMem(u64, Box<ESILNode>, Box<ESILNode>),
    OrAssignMem(u64, Box<ESILNode>, Box<ESILNode>),
    XorAssignMem(u64, Box<ESILNode>, Box<ESILNode>),

    IncAssignMem(u64, Box<ESILNode>),
    DecAssignMem(u64, Box<ESILNode>),

    ShiftLeftAssignMem(u64, Box<ESILNode>, Box<ESILNode>),
    ShiftRightAssignMem(u64, Box<ESILNode>, Box<ESILNode>),

    BitAndAssign(Box<ESILNode>, Box<ESILNode>),
    BitOrAssign(Box<ESILNode>, Box<ESILNode>),
    BitXorAssign(Box<ESILNode>, Box<ESILNode>),
    NotAssign(Box<ESILNode>),

    LoadMem(Box<ESILNode>),
    LoadMemSized(u64, Box<ESILNode>),
    LoadMemMulti(Box<ESILNode>, Vec<Box<ESILNode>>),

    Assign(Box<ESILNode>, Box<ESILNode>),
    BitAssign(Box<ESILNode>, Box<ESILNode>),
    AssignMem(Box<ESILNode>, Box<ESILNode>),
    AssignMemSized(u64, Box<ESILNode>, Box<ESILNode>),
    AssignMemMulti(Box<ESILNode>, Vec<Box<ESILNode>>),
    SignExt(Box<ESILNode>),
    AssignSignExt(Box<ESILNode>, Box<ESILNode>),

    Eq(Box<ESILNode>, Box<ESILNode>),
    Less(Box<ESILNode>, Box<ESILNode>),
    LessEq(Box<ESILNode>, Box<ESILNode>),
    Greater(Box<ESILNode>, Box<ESILNode>),
    GreaterEq(Box<ESILNode>, Box<ESILNode>),

    ConditionalStart(Box<ESILNode>),
    ConditionalNotElse,
    ConditionalEnd(Box<ESILNode>, Vec<Box<ESILNode>>, Vec<Box<ESILNode>>),

    Skip,
    Loop,
    Break,
    Stack,
    Clear,
    Goto,

    Todo,

    Syscall,
    InstructionAddr,

    D2F(Box<ESILNode>),
    F2D(Box<ESILNode>),
    I2D(Box<ESILNode>),
    D2I(Box<ESILNode>),
    FEq(Box<ESILNode>, Box<ESILNode>),
    FNeq(Box<ESILNode>, Box<ESILNode>),
    FLess(Box<ESILNode>, Box<ESILNode>),
    FLessEq(Box<ESILNode>, Box<ESILNode>),
    FAdd(Box<ESILNode>, Box<ESILNode>),
    FSub(Box<ESILNode>, Box<ESILNode>),
    FMul(Box<ESILNode>, Box<ESILNode>),
    FDiv(Box<ESILNode>, Box<ESILNode>),
    Ceil(Box<ESILNode>),
    Floor(Box<ESILNode>),
    Round(Box<ESILNode>),
    Sqrt(Box<ESILNode>),
    Nan(Box<ESILNode>),
}

#[derive(Parser)]
#[grammar = "esil.pest"]
struct ESILParser;

impl ESILNode {
    pub fn from(esil: &String) -> Vec<Box<ESILNode>> {
        // FIXME: Improve Error Reporting
        let stack = Vec::new();
        if esil.starts_with(",") || esil == "" {
            return stack;
        }
        let mut parsed = ESILParser::parse(Rule::top, esil).expect(&format!("Could not parse ESIL: {:?}", esil)[..]);
        trace!("Translating ESIL {:?}", esil);
        let result = build_tree(parsed.next().unwrap(), stack);
        trace!("Result: {:#?}", result);
        result
    }
}

fn find_operand(stack: &mut Vec<Box<ESILNode>>) -> Box<ESILNode> {
    let mut unused = Vec::new();

    loop {
        let elem = stack.pop()
            .expect(&format!("Stack empty while looking for operand, skipped: {:?}", unused)[..]);
        let keep: bool;

        keep = match *elem {
            ESILNode::Assign(_, _) |
            ESILNode::BitAssign(_, _) |
            ESILNode::AssignMem(_, _) |
            ESILNode::AssignMemSized(_, _, _) |
            ESILNode::AssignMemMulti(_, _) |
            ESILNode::AssignSignExt(_, _) |
            ESILNode::AddAssign(_, _) |
            ESILNode::SubAssign(_, _) |
            ESILNode::MulAssign(_, _) |
            ESILNode::DivAssign(_, _) |
            ESILNode::ModAssign(_, _) |
            ESILNode::IncAssign(_) |
            ESILNode::DecAssign(_) |
            ESILNode::ShiftLeftAssign(_, _) |
            ESILNode::ShiftRightAssign(_, _) |
            ESILNode::AddAssignMem(_, _, _) |
            ESILNode::SubAssignMem(_, _, _) |
            ESILNode::MulAssignMem(_, _, _) |
            ESILNode::DivAssignMem(_, _, _) |
            ESILNode::ModAssignMem(_, _, _) |
            ESILNode::IncAssignMem(_, _) |
            ESILNode::DecAssignMem(_, _) |
            ESILNode::ShiftLeftAssignMem(_, _, _) |
            ESILNode::ShiftRightAssignMem(_, _, _) |
            ESILNode::ArithShiftLeftAssign(_, _) |
            ESILNode::ArithShiftRightAssign(_, _) |
            ESILNode::BitAndAssign(_, _) |
            ESILNode::BitOrAssign(_, _) |
            ESILNode::BitXorAssign(_, _) |
            ESILNode::NotAssign(_) |
            ESILNode::Skip |
            ESILNode::Loop |
            ESILNode::Break |
            ESILNode::Stack |
            ESILNode::Clear |
            ESILNode::Goto |
            ESILNode::Todo |
            ESILNode::Syscall => true,
            _ => false,
        };

        // XXX How to handle conditionals here?

        if keep {
            unused.push(elem);
        } else {
            for i in unused.iter().rev() {
                stack.push(i.clone());
            }
            return elem;
        }
    }
}

macro_rules! op1 {
    ($stack:ident, $node_name:ident) => {
        {
            let arg1 = find_operand(&mut $stack);
            $stack.push(Box::new(ESILNode::$node_name(arg1)));
        }
    }
}
macro_rules! op2 {
    ($stack:ident, $node_name:ident) => {
        {
            let arg1 = find_operand(&mut $stack);
            let arg2 = find_operand(&mut $stack);
            $stack.push(Box::new(ESILNode::$node_name(arg1, arg2)));
        }
    }
}
macro_rules! op1m {
    ($stack:ident, $node_name:ident, $p:ident) => {
        {
            let arg1 = find_operand(&mut $stack);
            let size = u64::from_str_radix($p.into_inner().next().unwrap().as_span().as_str(), 10).unwrap();
            $stack.push(Box::new(ESILNode::$node_name(size, arg1)));
        }
    }
}
macro_rules! op2m {
    ($stack:ident, $node_name:ident, $p:ident) => {
        {
            let arg1 = find_operand(&mut $stack);
            let arg2 = find_operand(&mut $stack);
            let size = u64::from_str_radix($p.into_inner().next().unwrap().as_span().as_str(), 10).unwrap();
            $stack.push(Box::new(ESILNode::$node_name(size, arg1, arg2)));
        }
    }
}

pub fn build_tree(p: Pair<Rule>, old_stack: Vec<Box<ESILNode>>) -> Vec<Box<ESILNode>> {
    let mut stack = old_stack.clone();
    trace!("Building Tree from {:#?}", p);

    match p.as_rule() {
        Rule::commands | Rule::if_branch | Rule::else_branch => return p.into_inner().fold(stack, |old_stack, x| {
            // trace!("Building stuff for {:?}", x);
            trace!("parsing next element {:?}", x);
            let result = build_tree(x, old_stack);
            // trace!("result: {:?}", result);
            result
        }),
        Rule::hex_number => stack.push(Box::new(ESILNode::Imm(
            i128::from_str_radix(p.as_span().as_str().trim_start_matches("0x"), 16).unwrap(),
        ))),
        Rule::dec_number => stack.push(Box::new(ESILNode::Imm(
            i128::from_str_radix(p.as_span().as_str(), 10).unwrap(),
        ))),
        Rule::others => stack.push(Box::new(ESILNode::Reg(String::from(p.as_span().as_str())))),
        Rule::op_assign    => op2!(stack, Assign),
        Rule::op_bitassign => op2!(stack, BitAssign),
        Rule::op_signext   => op1!(stack, SignExt),
        Rule::op_assignsignext => op2!(stack, AssignSignExt),
        Rule::op_add => op2!(stack, Add),
        Rule::op_sub => op2!(stack, Sub),
        Rule::op_mul => op2!(stack, Mul),
        Rule::op_div => op2!(stack, Div),
        Rule::op_mod => op2!(stack, Mod),
        Rule::op_shiftleft => op2!(stack, ShiftLeft),
        Rule::op_shiftright => op2!(stack, ShiftRight),
        Rule::op_rotleft => op2!(stack,  RotLeft),
        Rule::op_rotright => op2!(stack, RotRight),
        Rule::op_arithshiftleft => op2!(stack,  ArithShiftLeft),
        Rule::op_arithshiftright => op2!(stack, ArithShiftRight),
        Rule::op_bitand => op2!(stack, BitAnd),
        Rule::op_bitor => op2!(stack, BitOr),
        Rule::op_bitxor => op2!(stack, BitXor),
        Rule::op_not => op1!(stack, Not),
        Rule::op_eq => op2!(stack, Eq),
        Rule::op_less => op2!(stack, Less),
        Rule::op_lesseq => op2!(stack, LessEq),
        Rule::op_greater => op2!(stack, Greater),
        Rule::op_greatereq => op2!(stack, GreaterEq),

        Rule::op_addassign => op2!(stack, AddAssign),
        Rule::op_subassign => op2!(stack, SubAssign),
        Rule::op_mulassign => op2!(stack, MulAssign),
        Rule::op_divassign => op2!(stack, DivAssign),
        Rule::op_modassign => op2!(stack, ModAssign),
        Rule::op_incassign => op1!(stack, IncAssign),
        Rule::op_decassign => op1!(stack, DecAssign),

        Rule::op_shiftleftassign => op2!(stack, ShiftLeftAssign),
        Rule::op_shiftrightassign => op2!(stack, ShiftRightAssign),
        Rule::op_arithshiftleftassign => op2!(stack,  ArithShiftLeftAssign),
        Rule::op_arithshiftrightassign => op2!(stack, ArithShiftRightAssign),

        Rule::op_addassignmem => op2m!(stack, AddAssignMem, p),
        Rule::op_subassignmem => op2m!(stack, SubAssignMem, p),
        Rule::op_mulassignmem => op2m!(stack, MulAssignMem, p),
        Rule::op_divassignmem => op2m!(stack, DivAssignMem, p),
        Rule::op_incassignmem => op1m!(stack, IncAssignMem, p),
        Rule::op_decassignmem => op1m!(stack, DecAssignMem, p),

        Rule::op_andassignmem => op2m!(stack, AndAssignMem, p),
        Rule::op_orassignmem => op2m!(stack, OrAssignMem, p),
        Rule::op_xorassignmem => op2m!(stack, XorAssignMem, p),

        Rule::op_shiftleftassignmem => op2m!(stack, ShiftLeftAssignMem, p),
        Rule::op_shiftrightassignmem => op2m!(stack, ShiftRightAssignMem, p),

        Rule::op_inc => op1!(stack, Inc),
        Rule::op_dec => op1!(stack, Dec),

        Rule::op_bitandassign => op2!(stack, BitAndAssign),
        Rule::op_bitorassign => op2!(stack, BitOrAssign),
        Rule::op_bitxorassign => op2!(stack, BitXorAssign),
        Rule::op_notassign => op1!(stack, NotAssign),

        Rule::op_syscall => { warn!("NUM is unsupported"); },
        Rule::op_instructionaddr => {
            warn!("$$ is unsupported");
            stack.push(Box::new(ESILNode::InstructionAddr))
        },
        Rule::op_todo => (),

        Rule::op_num => { warn!("NUM is unsupported"); }, // not supported
        Rule::op_skip => { warn!("SKIP is unsupported"); }, // not supported
        Rule::op_loop => { warn!("LOOP is unsupported"); }, // not supported
        Rule::op_break => { warn!("BREAK is unsupported"); }, // not supported
        Rule::op_stack =>  { warn!("STACK is unsupported"); }, // not supported
        Rule::op_clear =>  { warn!("CLEAR is unsupported"); }, // not supported

        Rule::flg_zero => { warn!("$z is unsupported"); stack.push(Box::new(ESILNode::Flag("z".to_string()))) }, // not supported
        Rule::flg_parity => { warn!("$p is unsupported"); stack.push(Box::new(ESILNode::Flag("p".to_string()))) }, // not supported
        Rule::flg_carry => { warn!("$c is unsupported"); stack.push(Box::new(ESILNode::Flag("c".to_string()))) }, // not supported
        Rule::flg_borrow => { warn!("$b is unsupported"); stack.push(Box::new(ESILNode::Flag("b".to_string()))) }, // not supported
        Rule::flg_sign => { warn!("$s is unsupported"); stack.push(Box::new(ESILNode::Flag("b".to_string()))) }, // not supported
        Rule::flg_regsize =>  { warn!("$r is unsupported"); stack.push(Box::new(ESILNode::Flag("r".to_string()))) }, // not supported

        Rule::op_dup => {
            let arg1 = find_operand(&mut stack);
            stack.push(arg1.clone());
            stack.push(arg1.clone());
        }
        Rule::op_swap => {
            let arg1 = find_operand(&mut stack);
            let arg2 = find_operand(&mut stack);
            stack.push(arg1.clone());
            stack.push(arg2.clone());
        },

        Rule::op_d2i => op1!(stack, D2I),
        Rule::op_i2d => op1!(stack, I2D),
        Rule::op_f2d => op1!(stack, F2D),
        Rule::op_d2f => op1!(stack, D2F),
        Rule::op_feq => op2!(stack, FEq),
        Rule::op_fneq => op2!(stack, FNeq),
        Rule::op_fless => op2!(stack, FLess),
        Rule::op_flesseq => op2!(stack, FLessEq),
        Rule::op_fadd => op2!(stack, FAdd),
        Rule::op_fsub => op2!(stack, FSub),
        Rule::op_fmul => op2!(stack, FMul),
        Rule::op_fdiv => op2!(stack, FDiv),
        Rule::op_floor => op1!(stack, Floor),
        Rule::op_round => op1!(stack, Round),
        Rule::op_sqrt => op1!(stack, Sqrt),
        Rule::op_nan => op1!(stack, Nan),
        Rule::op_assignmem => op2!(stack, AssignMem),
        Rule::op_assignmem_nonimm => {
            let arg1 = find_operand(&mut stack);
            let arg2 = find_operand(&mut stack);
            let mut targets = Vec::new();
            match *arg2 {
                ESILNode::Imm(n) => {
                    for _ in 0..n {
                        let arg3 = find_operand(&mut stack);
                        targets.push(arg3)
                    }
                }
                _ => panic!("cannot peek some with non-Imm size in ESIL"),
            }
            stack.push(Box::new(ESILNode::AssignMemMulti(arg1, targets)));
        }
        Rule::op_assignmem_sized => {
            let arg1 = find_operand(&mut stack);
            let arg2 = find_operand(&mut stack);
            trace!("sized store ! {:?} {:?}", arg1, arg2);
            let size = u64::from_str_radix(p.into_inner().next().unwrap().as_span().as_str(), 10).unwrap();
            stack.push(Box::new(ESILNode::AssignMemSized(size, arg1, arg2)));
        }

        Rule::op_load => op1!(stack, LoadMem),
        Rule::op_loadmem_nonimm => {
            let arg1 = find_operand(&mut stack);
            let arg2 = find_operand(&mut stack);
            let mut targets = Vec::new();
            match *arg2 {
                ESILNode::Imm(n) => {
                    for _ in 0..n {
                        let arg3 = find_operand(&mut stack);
                        targets.push(arg3)
                    }
                }
                _ => panic!("cannot peek some with non-Imm size in ESIL"),
            }
            stack.push(Box::new(ESILNode::LoadMemMulti(arg1, targets)));
        },

        Rule::op_loadmem_sized => op1m!(stack, LoadMemSized, p),

        Rule::conditional => {
            let arg = find_operand(&mut stack);
            let inner: Vec<_> = p.into_inner().collect();

            if inner.len() == 2 {
                stack.push(Box::new(ESILNode::ConditionalEnd(arg, build_tree(inner[0].clone(), stack.clone()), build_tree(inner[1].clone(), stack.clone()))));
            } else {
                stack.push(Box::new(ESILNode::ConditionalEnd(arg, build_tree(inner[0].clone(), stack.clone()), Vec::new())));
            }
        }


        _ => {
            warn!("ESIL grammar element not known: {:?}", p)
        }

    }
    stack
}
