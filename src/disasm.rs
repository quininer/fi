use std::{ fmt, slice };
use std::iter::Peekable;
use capstone::Capstone;

pub enum Disassembler {
    X86_64(Capstone),
    Aarch64(Capstone),
    Wasm,
}

pub enum InstList<'a> {
    X86_64(capstone::Instructions<'a>),
    Aarch64(capstone::Instructions<'a>),
    Wasm(wasmparser::FunctionBody<'a>)
}

pub enum InstIter<'a> {
    X86_64(slice::Iter<'a, capstone::Insn<'a>>),
    Aarch64(slice::Iter<'a, capstone::Insn<'a>>),
    Wasm {
        base: usize,
        data: &'a [u8],
        iter: Peekable<wasmparser::OperatorsIteratorWithOffsets<'a>>,
    },
}

pub enum Inst<'a> {
    X86_64(&'a capstone::Insn<'a>),
    Aarch64(&'a capstone::Insn<'a>),
    Wasm {
        data: &'a [u8],
        offset: usize,
        operator: wasmparser::Operator<'a>
    }
}

impl Disassembler {
    pub fn new(obj: &object::File) -> anyhow::Result<Disassembler> {
        use object::Object;
        use capstone::Capstone;
        use capstone::arch::BuildsCapstone;
    
        let disasm = match obj.architecture() {
            object::Architecture::X86_64 => Capstone::new()
                .x86()
                .mode(capstone::arch::x86::ArchMode::Mode64)
                .detail(true)
                .build()
                .map(Disassembler::X86_64)?,
            object::Architecture::Aarch64 => Capstone::new()
                .arm64()
                .mode(capstone::arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .map(Disassembler::Aarch64)?,
            object::Architecture::Wasm32
                | object::Architecture::Wasm64 => Disassembler::Wasm,
            arch => anyhow::bail!("unsupported arch: {:?}", arch)
        };

        Ok(disasm)
    }

    pub fn disasm_all<'a>(&'a self, code: &'a [u8], addr: u64) -> anyhow::Result<InstList<'a>> {
        let list = match self {
            Disassembler::X86_64(disasm) => disasm.disasm_all(code, addr).map(InstList::X86_64)?,
            Disassembler::Aarch64(disasm) => disasm.disasm_all(code, addr).map(InstList::Aarch64)?,
            Disassembler::Wasm => {
                let reader = wasmparser::BinaryReader::new(code, addr.try_into()?);
                let func = wasmparser::FunctionBody::new(reader);
                InstList::Wasm(func)
            }
        };

        Ok(list)
    }

    pub fn operand2addr(&self, inst: &Inst<'_>) -> anyhow::Result<Option<u64>> {
        use capstone::arch::{ ArchDetail, DetailsArchInsn };
        use capstone::InsnGroupType::{ Type as InsnGroupType, CS_GRP_CALL, CS_GRP_JUMP };
        
        match (self, inst) {
            (Disassembler::X86_64(disasm), Inst::X86_64(inst)) => {
                use capstone::arch::x86::X86OperandType;
                use capstone::arch::x86::X86Reg::{ Type as X86RegType, X86_REG_RIP };

                let Ok(detail) = disasm.insn_detail(inst)
                    else {
                        return Ok(None);
                    };
                let Some(_group_id) = detail.groups()
                    .iter()
                    .map(|id| InsnGroupType::from(id.0))
                    .find(|&id| matches!(id, CS_GRP_CALL | CS_GRP_JUMP))
                else {
                    return Ok(None)
                };

                Ok(match detail.arch_detail() {
                    ArchDetail::X86Detail(inst_detail) => {
                        let Some(operand) = inst_detail.operands().next()
                            else {
                                return Ok(None)
                            };

                        match operand.op_type {
                            X86OperandType::Imm(imm) => imm.try_into().ok().map(|addr: u64| addr),
                            X86OperandType::Mem(mem)
                                if X86RegType::from(mem.base().0) == X86_REG_RIP =>
                            {
                                inst.address().checked_add_signed(mem.disp())
                            },
                            _ => None
                        }
                    },
                    _ => None
                })
            },
            (Disassembler::Aarch64(disasm), Inst::Aarch64(inst)) => {
                use capstone::arch::arm64::Arm64OperandType;

                let Ok(detail) = disasm.insn_detail(inst)
                    else {
                        return Ok(None);
                    };
                let Some(_group_id) = detail.groups()
                    .iter()
                    .map(|id| InsnGroupType::from(id.0))
                    .find(|&id| matches!(id, CS_GRP_CALL | CS_GRP_JUMP))
                else {
                    return Ok(None)
                };

                Ok(match detail.arch_detail() {
                    ArchDetail::Arm64Detail(inst_detail) => {
                        let Some(operand) = inst_detail.operands().next()
                            else {
                                return Ok(None)
                            };

                        match operand.op_type {
                            Arm64OperandType::Imm(imm) => imm.try_into()
                                .ok()
                                .map(|addr: u64| addr),
                            _ => None
                        }
                    },
                    _ => None
                })                
            },
            _ => anyhow::bail!("unsupported arch")
        }
    }
}

impl<'a> InstList<'a> {
    pub fn iter(&self) -> anyhow::Result<InstIter<'_>> {
        let iter = match self {
            InstList::X86_64(list) => InstIter::X86_64(list.iter()),
            InstList::Aarch64(list) => InstIter::Aarch64(list.iter()),
            InstList::Wasm(func) => {
                let base = func.range().start;
                let data = func.as_bytes();
                let iter = func.get_operators_reader()?
                    .into_iter_with_offsets()
                    .peekable();
                InstIter::Wasm { base, data, iter }
            },
        };

        Ok(iter)
    }
}

impl<'a> Iterator for InstIter<'a> {
    type Item = anyhow::Result<Inst<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            InstIter::X86_64(iter) => iter.next().map(Inst::X86_64).map(Ok),
            InstIter::Aarch64(iter) => iter.next().map(Inst::Aarch64).map(Ok),
            InstIter::Wasm { base, data, iter } => {
                let next = iter.next();
                let peek = iter.peek()
                    .and_then(|inst| inst.as_ref().ok())
                    .map(|(_op, offset)| *offset);

                next.map(|result| result
                    .map(|(operator, offset)| {
                        let base = offset - *base;
                        let mut data = &data[base..];
                        if let Some(peek) = peek {
                            data = &data[..peek - offset];
                        }
                        Inst::Wasm { data, offset, operator }
                    })
                    .map_err(Into::into)
                )
            }
        }
    }
}

impl Inst<'_> {
    pub fn address(&self) -> u64 {
        match self {
            Inst::X86_64(inst) => inst.address(),
            Inst::Aarch64(inst) => inst.address(),
            Inst::Wasm { offset, .. } => (*offset) as u64
        }
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            Inst::X86_64(inst) => inst.bytes(),
            Inst::Aarch64(inst) => inst.bytes(),
            Inst::Wasm { data, .. } => data
        }
    }
}

impl fmt::Display for Inst<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Inst::X86_64(inst) | Inst::Aarch64(inst) => {
                write!(f, "{}", inst.mnemonic().unwrap_or("???"))?;

                if let Some(op_str) = inst.op_str() {
                    write!(f, " {}", op_str)?;
                }

                Ok(())
            },
            Inst::Wasm { operator, .. } => fmt::Debug::fmt(&operator, f)
        }
    }
}
