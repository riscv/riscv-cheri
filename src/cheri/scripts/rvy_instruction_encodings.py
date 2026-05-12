#!/usr/bin/env python3
import re
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Optional, Union

COLOR_HEADER = "DDEBF7"
COLOR_FIXED = "D9EAD3"
COLOR_VAR = "FFF2CC"

NEQ = "\u2260"
CS1_NEQ_X0 = f"{{cs1}}{NEQ}0"
RS2_NEQ_X0 = f"rs2{NEQ}0"


class MajorOpcode(Enum):
    LOAD = 0b0000011
    MISC_MEM = 0b0001111
    OP_IMM = 0b0010011
    OP_IMM_32 = 0b0011011
    STORE = 0b0100011
    AMO = 0b0101111
    OP = 0b0110011
    SYSTEM = 0b1110011
    RVY_B = 0b1011011
    RVY_A = 0b1111011


class Funct3(Enum):
    @property
    def bits(self):
        return self.value[0]

    @property
    def asciidoc_label(self):
        return self.value[2]


class Custom3Funct3(Funct3):
    REGULAR = 0b000, "R-Type (3-op and 1/2-op)", "RVY-R"
    LY = 0b001, "LY", "{LOAD_CAP_NAME}"
    SY = 0b010, "SY", "{STORE_CAP_NAME}"
    AMO = 0b011, "AMO", "RVY-AMO"
    YADDI = 0b100, "YADDI", "{CADDI}"
    MISC = 0b101, "MISC IMM (SRLIY/YBNDSWI)", "RVY-MISC"
    RES6 = 0b110, "*Unallocated*", "RVY-RES6"
    RES7 = 0b111, "*Unallocated*", "RVY-RES7"

    @classmethod
    def get_map(cls):
        return {item.value[0]: item.value[1] for item in cls}


def fmt_bin(val: Union[str, int, MajorOpcode, Funct3], bits=None):
    if val is None:
        return ""
    if isinstance(val, Funct3):
        val = val.bits
    if isinstance(val, MajorOpcode):
        val = val.value
    if isinstance(val, int):
        return format(val, f'0{bits}b') if bits else bin(val)[2:]
    return str(val)


class CellType(Enum):
    OPCODE = COLOR_FIXED, 8, True
    FUNCT = COLOR_FIXED, 3, True
    FUNCT_OP = COLOR_FIXED, 8, True
    FIXED = COLOR_FIXED, 3, True
    DEST = COLOR_VAR, 2, False
    SRC = COLOR_VAR, 4, False
    IMM = COLOR_VAR, 4, False
    IMM_FIXED = COLOR_FIXED, 3, True
    HEADER = COLOR_HEADER, 5, True

    @property
    def fill_color(self):
        return self.value[0]

    @property
    def wavedrom_type(self):
        return self.value[1]

    @property
    def is_fixed(self):
        return self.value[2]


class InsnBitsCell:
    def __init__(
        self,
        val: Union[str, int, MajorOpcode, Funct3],
        start: int,
        end: int,
        cell_type: CellType,
        *,
        name: Optional[str] = None,
        wavedrom_label: Optional[str] = None,
    ):
        self.val = val
        self.start = start
        self.end = end
        self.name = name
        self.cell_type = cell_type
        self.wavedrom_label = wavedrom_label

    @property
    def bit_str(self) -> str:
        return fmt_bin(self.val, self.start - self.end + 1)

    @property
    def is_fixed(self):
        return self.cell_type.is_fixed

    # Note on field representations:
    # Wavedrom wants the names of the fields inside the diagram (e.g. "funct7"), and the actual values
    # as labels underneath (e.g. "RVY-A=1111011").
    # However, the encoding overview (XLSX, bytefield) just has a single box per field, so we put the
    # actual value (e.g. "0000001" or "RVY-A=1111011") directly in there.

    @property
    def value_for_wavedrom(self) -> str:
        if not self.is_fixed:
            return str(self.val)
        return self.name if self.name is not None else self.bit_str

    @property
    def value_for_encoding_overview(self) -> str:
        if isinstance(self.val, MajorOpcode) and self.wavedrom_label:
            return self.wavedrom_label
        if self.is_fixed:
            return self.bit_str
        return str(self.val)


def make_insn_bits(val, start, end, *, name: str, cell_type: Optional[CellType] = None, wavedrom_label: Optional[str] = None, **kwargs):
    if cell_type is None:
        cell_type = CellType.FIXED if isinstance(val, int) else CellType.SRC
    return InsnBitsCell(val, start, end, name=name, wavedrom_label=wavedrom_label, cell_type=cell_type, **kwargs)


class TableEntry:
    def __init__(self, name: str, ext: Optional[str] = None, comment: str = ""):
        self.name = name
        self.ext = ext
        self.comment = comment


class Instruction(TableEntry):
    def __init__(
        self,
        name: str,
        op: MajorOpcode,
        f3: Union[str, int, Funct3],
        ext: Optional[str] = None,
        comment: str = "",
        funct3_label: str = None,
    ):
        super().__init__(name, ext, comment)
        if funct3_label is None and isinstance(f3, Funct3):
            funct3_label = f"{f3.asciidoc_label}={format(f3.bits, '03b')}"
        op_label = op.name.replace("_", "-") + "=" + format(op.value, "07b")
        self.op = InsnBitsCell(
            op, 6, 0, name="opcode", wavedrom_label=op_label, cell_type=CellType.OPCODE
        )
        self.f3 = InsnBitsCell(f3, 14, 12, name="funct3", wavedrom_label=funct3_label, cell_type=CellType.FUNCT_OP)
        self.cells: list[InsnBitsCell] = [self.op, self.f3]

    def as_wavedrom(self, include_header: bool = False) -> list[str]:
        return self.as_merged_wavedrom([self], include_header)

    @property
    def is_post_v1(self) -> bool:
        return self.ext in ("Zybndsrdw", "Zyseal")

    @classmethod
    def as_merged_wavedrom(cls, instructions, include_header: bool = False, collapse_identical_labels: bool = True) -> list[str]:
        if not instructions:
            return []

        rep_insn = instructions[0]
        sorted_cells: list[InsnBitsCell] = list(sorted(rep_insn.cells, key=lambda c: c.end))

        # Check that all instructions have the same cell structure
        for insn in instructions[1:]:
            insn_cells = sorted(insn.cells, key=lambda c: c.end)
            if len(insn_cells) != len(sorted_cells):
                raise ValueError(
                    f"Instructions have different number of cells: {len(sorted_cells)} vs {len(insn_cells)}"
                )
            for c1, c2 in zip(sorted_cells, insn_cells):
                if c1.start != c2.start or c1.end != c2.end:
                    raise ValueError(f"Cell bits mismatch: [{c1.start}:{c1.end}] vs [{c2.start}:{c2.end}]")

        lines = []
        if include_header:
            lines.extend(["[wavedrom, ,svg,subs=attributes+]", "...."])
        lines.append("{reg: [")

        for i, rep_cell in enumerate(sorted_cells):
            bits = rep_cell.start - rep_cell.end + 1
            type_val = rep_cell.cell_type.wavedrom_type
            attr_vals = []

            for insn in instructions:
                insn_cells = sorted(insn.cells, key=lambda c: c.end)
                target_cell = insn_cells[i]

                attr_val = target_cell.wavedrom_label
                if not collapse_identical_labels or attr_val not in attr_vals:
                    attr_vals.append(attr_val)

            display_name = rep_cell.value_for_wavedrom
            attr = f"['{bits}', " + ", ".join(f"'{a}'" for a in attr_vals) + "]"

            formatted_name = f"'{display_name}',"
            lines.append(
                f"  {{bits: {bits:2d}, name: {formatted_name:<13s} attr: {attr + ',':<26s} type: {type_val}}},"
            )

        lines.append("]}")
        if include_header:
            lines.append("....")
        return lines


class RType(Instruction):
    def __init__(
        self,
        name: str,
        op: MajorOpcode,
        f3: Union[str, int, Funct3],
        f7: Union[str, int] = 0,
        rs2: Union[str, int, None] = "rs2",
        rs1: Union[str, int, None] = "rs1",
        rd: Union[str, int, None] = "rd",
        ext: Optional[str] = None,
        comment: str = "",
        rd_label: Optional[str] = "dest",
        rs1_label: Optional[str] = "src1",
        rs2_label: Optional[str] = "src2",
        f7_label: str = "funct7",
    ):
        super().__init__(name, op, f3, ext, comment)
        self.f7 = make_insn_bits(f7, 31, 25, name="funct7", wavedrom_label=f7_label, cell_type=CellType.FUNCT)
        self.rs2 = make_insn_bits(rs2, 24, 20, name="rs2", wavedrom_label=rs2_label)
        self.rs1 = make_insn_bits(rs1, 19, 15, name="rs1", wavedrom_label=rs1_label)
        self.rd = make_insn_bits(rd, 11, 7, name="rd", wavedrom_label=rd_label, cell_type=CellType.DEST)
        self.cells.extend([self.f7, self.rs2, self.rs1, self.rd])


@lru_cache(maxsize=None)
def get_macro_to_insn_mapping():
    mapping = {}
    attr_file = Path(__file__).absolute().parent.parent / "attributes.adoc"
    assert attr_file.exists()
    with attr_file.open("r") as f:
        for line in f.readlines():
            m = re.match(r"^:([A-Z0-9_]+):\s+([A-Z0-9_.]+)\s*$", line)
            if m:
                mapping[m.group(1)] = m.group(2)
    return mapping

@lru_cache(maxsize=None)
def _get_macro_mapping():
    return {v: k for k, v in get_macro_to_insn_mapping().items()}


def _get_asciidoc_insn_name(name: str) -> str:
    base_name = name.split()[0]
    macro_map = _get_macro_mapping()
    result = macro_map.get(base_name)
    assert result is not None, f"could not find asciidoc name for {name}"
    return "{" + result + "}"


def insn_xref(i: Instruction, use_guards: bool = True) -> str:
    name = i.name
    if not name or name in ("1OP/2OP", "*Unallocated*"):
        return name
    anchor = _get_macro_mapping().get(name)
    if name == "LR.Y":
        anchor = "LOAD_RES_CAP"
    elif name == "SC.Y":
        anchor = "STORE_COND_CAP"
    elif name == "AMOSWAP.Y":
        anchor = "AMOSWAP_CAP"
    elif name == "LY":
        anchor = "LOAD_CAP"
    elif name == "SY":
        anchor = "STORE_CAP"
    xref = f"<<{anchor},{name}>>" if anchor else f"<<{name}>>"
    if use_guards and i.is_post_v1:
        return f"\nifndef::cheri_ratification_v1_only[]\n{xref}\nendif::[]\n"
    return xref


class RVYRType3Op(RType):
    def __init__(self, name: str, f7: Union[str, int], f7_label: Optional[str] = None, **kwargs):
        kwargs.setdefault("rd_label", "dest")
        kwargs.setdefault("rs1_label", "src1")
        kwargs.setdefault("rs2_label", "src2")
        if f7_label is None:
            f7_label = f"{_get_asciidoc_insn_name(name)}={format(f7, '07b')}"
        super().__init__(name, op=MajorOpcode.RVY_A, f3=Custom3Funct3.REGULAR, f7=f7, f7_label=f7_label, **kwargs)


class RVYRType2Op(RType):
    def __init__(self, name: str, rs2: Union[str, int], f7: int, rs2_label=None, **kwargs):
        kwargs.setdefault("rd_label", "dest")
        kwargs.setdefault("rs1_label", "src")
        if rs2_label is None:
            rs2_label = f"{_get_asciidoc_insn_name(name)}={format(rs2, '05b')}"
        f7_label = (
            "RVY-2OP-" + ("Y" if f7 & (1 << 1) else "X") + ("Y" if f7 & (1 << 0) else "X") + "=" + format(f7, "07b")
        )
        super().__init__(
            name,
            op=MajorOpcode.RVY_A,
            f3=Custom3Funct3.REGULAR,
            f7=f7,
            rs2=rs2,
            rs2_label=rs2_label,
            f7_label=f7_label,
            **kwargs,
        )
        self.rs2.name = "funct5"


class IType(Instruction):
    def __init__(
        self,
        name: str,
        op: MajorOpcode,
        f3: Union[str, int, Funct3],
        imm: str = "imm[11:0]",
        fixed: Optional[str] = None,
        rs1: Union[str, int, None] = "rs1",
        rd: Union[str, int, None] = "rd",
        ext: Optional[str] = None,
        comment: str = "",
        rd_label: str = "dest",
        rs1_label: str = "src",
        imm_label: str = "imm",
        fixed_label: Optional[str] = None,
        fixed_name: Optional[str] = None,
    ):
        super().__init__(name, op, f3, ext, comment)
        if fixed:
            if fixed_name is None:
                fixed_name = f"funct{len(fixed)}"
            if fixed_label is None:
                fixed_label = f"{_get_asciidoc_insn_name(name)}={fixed}"
            self.imm_high = InsnBitsCell(
                fixed, 31, 31 - len(fixed) + 1, name=fixed_name, wavedrom_label=fixed_label, cell_type=CellType.IMM_FIXED
            )
            self.imm_low = InsnBitsCell(imm, 31 - len(fixed), 20, name="imm", wavedrom_label=imm_label, cell_type=CellType.IMM)
            self.cells.extend([self.imm_high, self.imm_low])
        else:
            self.imm = InsnBitsCell(imm, 31, 20, name="imm", wavedrom_label=imm_label, cell_type=CellType.IMM)
            self.cells.append(self.imm)
        self.rs1 = make_insn_bits(rs1, 19, 15, name="rs1", wavedrom_label=rs1_label, cell_type=CellType.SRC)
        self.rd = make_insn_bits(rd, 11, 7, name="rd", wavedrom_label=rd_label, cell_type=CellType.DEST)
        self.cells.extend([self.rs1, self.rd])


class SType(Instruction):
    def __init__(
        self,
        name: str,
        op: MajorOpcode,
        f3: Union[str, int, Funct3],
        rs2: Union[str, int, None] = "rs2",
        rs1: Union[str, int, None] = "rs1",
        ext: Optional[str] = None,
        comment: str = "",
        rs1_label: str = "src",
        rs2_label: str = "src2",
        imm1_label: str = "offset[11:5]",
        imm2_label: str = "offset[4:0]",
    ):
        super().__init__(name, op, f3, ext, comment)
        self.imm1 = InsnBitsCell(imm1_label, 31, 25, name="imm", wavedrom_label=imm1_label, cell_type=CellType.IMM)
        self.rs2 = make_insn_bits(
            rs2, 24, 20, name="rs2", wavedrom_label=rs2_label, cell_type=CellType.FIXED if isinstance(rs2, int) else CellType.SRC
        )
        self.rs1 = make_insn_bits(rs1, 19, 15, name="rs1", wavedrom_label=rs1_label, cell_type=CellType.SRC)
        self.imm2 = InsnBitsCell(imm2_label, 11, 7, name="imm", wavedrom_label=imm2_label, cell_type=CellType.IMM)
        self.cells.extend([self.imm1, self.rs2, self.rs1, self.imm2])


class AMOType(Instruction):
    def __init__(
        self,
        name: str,
        op: MajorOpcode,
        f3: Union[str, int, Funct3],
        f5: Union[str, int] = 0,
        rs2: Union[str, int, None] = "rs2",
        rs1: Union[str, int, None] = "rs1",
        rd: Union[str, int, None] = "rd",
        ext: Optional[str] = None,
        comment: str = "",
        rd_label: Optional[str] = "dest",
        rs1_label: Optional[str] = "src",
        rs2_label: Optional[str] = "src2",
        f5_label: Optional[str] = None,
    ):
        super().__init__(name, op, f3, ext, comment)
        wavedrom_label = f5_label if f5_label else format(f5, "05b")
        self.f5_fixed = InsnBitsCell(f5, 31, 27, name="funct5", wavedrom_label=wavedrom_label, cell_type=CellType.FUNCT)
        self.aq = InsnBitsCell("aq", 26, 26, name="aq", wavedrom_label="aq", cell_type=CellType.SRC)
        self.rl = InsnBitsCell("rl", 25, 25, name="rl", wavedrom_label="rl", cell_type=CellType.SRC)
        self.rs2 = make_insn_bits(
            rs2, 24, 20, name="rs2", wavedrom_label=rs2_label, cell_type=CellType.FIXED if isinstance(rs2, int) else CellType.SRC
        )
        self.rs1 = make_insn_bits(rs1, 19, 15, name="rs1", wavedrom_label=rs1_label, cell_type=CellType.SRC)
        self.rd = make_insn_bits(rd, 11, 7, name="rd", wavedrom_label=rd_label, cell_type=CellType.DEST)
        self.cells.extend([self.f5_fixed, self.aq, self.rl, self.rs2, self.rs1, self.rd])


@dataclass
class RVYInstructions:
    regular_3op_insns: list[RVYRType3Op]
    regular_2op_insns: list[RVYRType2Op]
    yaddi: IType
    ly: IType
    sy: SType
    amo_insns: list[AMOType]
    misc_insns: list[Instruction]

    def all_instructions(self) -> list[Instruction]:
        return (
            self.regular_3op_insns
            + self.regular_2op_insns
            + [self.yaddi, self.ly, self.sy]
            + self.amo_insns
            + self.misc_insns
        )

    def __iter__(self):
        return iter(self.all_instructions())


@lru_cache(maxsize=1)
def get_custom3_insts():
    last_r3_f7_high_bits = {x: -1 for x in range(0, 8)}
    last_r3_f7_idx = -1
    last_r2_f5_value = {x: -1 for x in range(0, 4)}

    def next_rtype(name: str, rd: str, rs1: str, rs2: str = "rs2", **kwargs):
        funct7_low = 0
        # bit 0 = rd cap/int
        # bit 1 = rs1 cap/int
        # bit 2 = rs1 cap/int
        # bits 3-6: instruction index, just increment for next free one
        if rd.startswith("{cd}"):
            funct7_low |= 1 << 0
        else:
            assert rd.startswith("rd")
        if rs1.startswith("{cs1}"):
            funct7_low |= 1 << 1
        else:
            assert rs1.startswith("rs1")
        if rs2.startswith("{cs2}"):
            funct7_low |= 1 << 2
        else:
            assert rs2.startswith("rs2")
        nonlocal last_r3_f7_high_bits
        funct7_high = last_r3_f7_high_bits[funct7_low] + 1
        last_r3_f7_high_bits[funct7_low] = funct7_high
        nonlocal last_r3_f7_idx
        last_r3_f7_idx = (funct7_high << 3) | funct7_low
        return RVYRType3Op(name, f7=last_r3_f7_idx, rd=rd, rs1=rs1, rs2=rs2, **kwargs)

    def next_r2type(name: str, rd: str, rs1: str, **kwargs):
        # funct7 values
        # bit 0 = rd cap/int
        # bit 1 = rs1 cap/int
        # bit 2 = always zero
        # bits 3-6: always 1
        funct7_low = 0
        if rd.startswith("{cd}"):
            funct7_low |= 1 << 0
        else:
            assert rd.startswith("rd")
        if rs1.startswith("{cs1}"):
            funct7_low |= 1 << 1
        else:
            assert rs1.startswith("rs1")
        nonlocal last_r2_f5_value
        funct5 = last_r2_f5_value[funct7_low] + 1
        last_r2_f5_value[funct7_low] = funct5
        return RVYRType2Op(name, f7=(0b1111 << 3 | funct7_low), rs2=funct5, rd=rd, rs1=rs1, **kwargs)

    regular_3op_insns = [
        next_rtype("YADD", rs2=RS2_NEQ_X0, rs1="{cs1}", rd="{cd}", rs1_label="src", rs2_label="increment"),
        # Explicit f7=last_r3_f7_idx to group with YADD
        RVYRType3Op(
            "YMV",
            f7=last_r3_f7_idx,
            f7_label="{CADD}=0000011",
            rs2=0b00000,
            rs1="{cs1}",
            rd="{cd}",
            rs1_label="src",
            rs2_label="{CMV}: rs2=x0",
        ),
        next_rtype("YADDRW", rs1="{cs1}", rd="{cd}", rs1_label="src", rs2_label="address"),
        next_rtype("YPERMC", rs1="{cs1}", rd="{cd}", rs1_label="src", rs2_label="mask"),
        next_rtype("PACKY", rs1="rs1", rd="{cd}"),
        next_rtype("YBNDSW", rs1="{cs1}", rd="{cd}"),
        next_rtype("YBNDSRW", rs1="{cs1}", rd="{cd}"),
        next_rtype("YEQ", rs1="{cs1}", rs2="{cs2}", rd="rd"),
        next_rtype("YSS", rs1="{cs1}", rs2="{cs2}", rd="rd"),
        next_rtype("YSUNSEAL", rs1="{cs1}", rs2="{cs2}", rd="{cd}"),
        next_rtype("YBLD", rs1="{cs1}", rs2="{cs2}", rd="{cd}"),
        next_rtype("YSEAL", rs1="{cs1}", rs2="{cs2}", rd="{cd}", ext="Zyseal"),
        next_rtype("YUNSEAL", rs1="{cs1}", rs2="{cs2}", rd="{cd}", ext="Zyseal"),
        next_rtype("YMODEW", rs1="{cs1}", rd=f"{{cd}}{NEQ}0", ext="Zyhybrid"),
        RVYRType3Op(
            "YMODESWY",
            f7=last_r3_f7_idx,
            f7_label="{SCMODE}=0110011",
            rs2=0,
            rs2_label="{MODESW_CAP}=00000",
            rs1="{cs1}=x0",
            rs1_label="{cs1}=x0",
            rd="{cd}=x0",
            rd_label="{cd}=x0",
            ext="Zyhybrid",
        ),
        RVYRType3Op(
            "YMODESWI",
            f7=last_r3_f7_idx,
            f7_label="{SCMODE}=0110011",
            rs2=1,
            rs2_label="{MODESW_INT}=00001",
            rs1="{cs1}=x0",
            rs1_label="{cs1}=x0",
            rd="{cd}=x0",
            rd_label="{cd}=x0",
            ext="Zyhybrid",
        ),
        next_rtype("YBNDSRDW", rs1="{cs1}", rd="{cd}", ext="Zybndsrdw"),
        next_rtype("YSH1ADD", rs1="rs1", rs2="{cs2}", rd="{cd}", ext="Zba"),
        next_rtype("YSH2ADD", rs1="rs1", rs2="{cs2}", rd="{cd}", ext="Zba"),
        next_rtype("YSH3ADD", rs1="rs1", rs2="{cs2}", rd="{cd}", ext="Zba"),
        next_rtype("YSH4ADD", rs1="rs1", rs2="{cs2}", rd="{cd}", ext="Zba + RV64"),
        next_rtype("YSH1ADD.UW", rs1="rs1", rs2="{cs2}", rd="{cd}", ext="Zba + RV64"),
        next_rtype("YSH2ADD.UW", rs1="rs1", rs2="{cs2}", rd="{cd}", ext="Zba + RV64"),
        next_rtype("YSH3ADD.UW", rs1="rs1", rs2="{cs2}", rd="{cd}", ext="Zba + RV64"),
        next_rtype("YSH4ADD.UW", rs1="rs1", rs2="{cs2}", rd="{cd}", ext="Zba + RV64"),
    ]
    regular_2op_insns = [
        next_r2type("YBASER", rs1="{cs1}", rd="rd"),
        next_r2type("YPERMR", rs1="{cs1}", rd="rd"),
        next_r2type("YTOPR", rs1="{cs1}", rd="rd"),
        next_r2type("YLENR", rs1="{cs1}", rd="rd"),
        next_r2type("YTAGR", rs1="{cs1}", rd="rd"),
        next_r2type("YTYPER", rs1="{cs1}", rd="rd"),
        next_r2type("YAMASK", rs1="{cs1}", rd="rd"),
        next_r2type("YSENTRY", rs1="{cs1}", rd="{cd}", ext="Zysentry"),
        next_r2type("YMODER", rs1="{cs1}", rd="rd", ext="Zyhybrid"),
    ]
    # Sort by register selector bits (0:2) first and the the instruction index)
    regular_3op_insns.sort(key=lambda i: (i.f7.val & 7, i.f7.val >> 3))
    regular_2op_insns.sort(key=lambda i: (i.f7.val & 7, i.f7.val >> 3))
    # use the same funct7 codes as the base AMO instructions (and a funct3 of 4 which would match Y width code)
    lr_f7 = 0b00010
    sc_f7 = 0b00011
    amoswap_f7 = 0b00001
    return RVYInstructions(
        regular_3op_insns=regular_3op_insns,
        regular_2op_insns=regular_2op_insns,
        yaddi=IType("YADDI", op=MajorOpcode.RVY_A, f3=Custom3Funct3.YADDI, rs1="{cs1}", rd="{cd}", imm_label="imm"),
        ly=IType(
            "LY",
            op=MajorOpcode.RVY_A,
            f3=Custom3Funct3.LY,
            rs1=CS1_NEQ_X0,
            rd="{cd}",
            imm_label="offset",
            rs1_label="base",
        ),
        sy=SType(
            "SY",
            op=MajorOpcode.RVY_A,
            f3=Custom3Funct3.SY,
            rs1=CS1_NEQ_X0,
            rs2="{cs2}",
            rs1_label="base",
            rs2_label="src",
        ),
        amo_insns=[
            AMOType(
                "LR.Y",
                op=MajorOpcode.RVY_A,
                f5=lr_f7,
                f3=Custom3Funct3.AMO,
                ext="Zalrsc",
                rs1=CS1_NEQ_X0,
                rs2=0b00000,
                rd="{cd}",
                rd_label="rd",
                rs1_label="base",
                f5_label=f"LR.*={format(lr_f7, '05b')}",
                comment="Same funct7 as base AMO encoding, funct3 to indicate Y operand",
            ),
            AMOType(
                "AMOSWAP.Y",
                op=MajorOpcode.RVY_A,
                f5=0b00001,
                f3=Custom3Funct3.AMO,
                ext="Zaamo",
                rs1=CS1_NEQ_X0,
                rs2="{cs2}",
                rd="{cd}",
                rd_label="rd",
                rs1_label="base",
                rs2_label="src",
                f5_label=f"SWAP={format(amoswap_f7, '05b')}",
                comment="Same funct7 as base AMO encoding, funct3 to indicate Y operand",
            ),
            AMOType(
                "SC.Y",
                op=MajorOpcode.RVY_A,
                f5=0b00011,
                f3=Custom3Funct3.AMO,
                ext="Zalrsc",
                rs1=CS1_NEQ_X0,
                rs2="{cs2}",
                rd="rd",
                rd_label="rd",
                rs1_label="base",
                rs2_label="src",
                f5_label=f"SC.*={format(sc_f7, '05b')}",
                comment="Same funct7 as base AMO encoding, funct3 indicate Y operand",
            ),
        ],
        misc_insns=[
            IType(
                "YHIR",
                op=MajorOpcode.RVY_A,
                f3=Custom3Funct3.MISC,
                imm="shamt=XLEN",
                fixed="0" * 5,
                rs1="{cs1}",
                rd="rd",
                imm_label="shamt=XLEN",
            ),
            IType("SRLIY", op=MajorOpcode.RVY_A, f3=Custom3Funct3.MISC, rs1="{cs1}", imm="shamt[6:0]", fixed="0" * 5),
            IType(
                "YBNDSWI",
                op=MajorOpcode.RVY_A,
                f3=Custom3Funct3.MISC,
                imm="ybndswimm[8:0]",
                fixed="111",
                rs1="{cs1}",
                rd="{cd}",
                rd_label="dest",
                rs1_label="src",
                imm_label="imm",
            ),
        ],
    )
