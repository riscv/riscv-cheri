#!/usr/bin/env python3
import sys
from rvy_instruction_encodings import get_custom3_insts, RType, IType, SType, AMOType

def generate_decodetree():
    instructions = get_custom3_insts()
    for insn in instructions:
        if insn.name == "YHIR":
            continue
        cells = sorted(insn.cells, key=lambda c: c.start, reverse=True)

        rd_is_c = False
        rs1_is_c = False
        rs2_is_c = False
        has_rs2 = False
        has_imm = False

        parts = []
        for cell in cells:
            val_str = str(cell.val)
            length = cell.start - cell.end + 1
            if cell.is_fixed:
                parts.append(cell.bit_str)
            else:
                parts.append("." * length)

            if cell.start == 11 and cell.end == 7:
                if "{cd}" in val_str: rd_is_c = True
            elif cell.start == 19 and cell.end == 15:
                if "{cs1}" in val_str: rs1_is_c = True
            elif cell.start == 24 and cell.end == 20:
                if not cell.is_fixed:
                    has_rs2 = True
                    if "{cs2}" in val_str: rs2_is_c = True
            elif not cell.is_fixed and cell.start not in (11, 19, 24, 26, 25):
                has_imm = True

        name_str = insn.name.lower().replace(".", "_").ljust(15)
        bits = "".join(parts)
        assert len(bits) == 32

        chunks = [
            bits[0:7],
            bits[7:12],
            bits[12:17],
            bits[17:20],
            bits[20:25],
            bits[25:32]
        ]

        if isinstance(insn, AMOType):
            format_tag = "@atom_ld" if insn.name.startswith("LR.") else "@atom_st"
        elif isinstance(insn, SType):
            format_tag = "@s"
        elif isinstance(insn, IType) or has_imm:
            rd_char = 'c' if rd_is_c else 'r'
            rs1_char = 'c' if rs1_is_c else 'r'
            format_tag = f"@{rd_char}{rs1_char}i"
            if format_tag == "@rri": format_tag = "@i"
        else:
            rd_char = 'c' if rd_is_c else 'r'
            rs1_char = 'c' if rs1_is_c else 'r'
            if has_rs2:
                rs2_char = 'c' if rs2_is_c else 'r'
                format_tag = f"@{rd_char}{rs1_char}{rs2_char}"
                if format_tag == "@rrr": format_tag = "@r"
            else:
                format_tag = f"@{rd_char}{rs1_char}"
                if format_tag == "@rr": format_tag = "@r2"

        print(f"{name_str} {' '.join(chunks)} {format_tag} ?pred_rvy".strip())

if __name__ == "__main__":
    generate_decodetree()
