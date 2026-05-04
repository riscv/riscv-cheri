#!/usr/bin/env python3
import sys
from rvy_instruction_encodings import get_custom3_insts

def generate_riscv_opcodes():
    instructions = get_custom3_insts()
    for insn in instructions:
        if insn.name == "YHIR":
            continue
        cells = sorted(insn.cells, key=lambda c: c.start, reverse=True)

        args = []
        fixed = []
        # Sort operands: rd, rs1, rs2, rs3, aq, rl, imm
        # This roughly matches the natural cell order from LSB to MSB (left to right)
        cells_ascending = sorted(insn.cells, key=lambda c: c.start)
        for cell in cells_ascending:
            if not cell.is_fixed:
                if cell.start == 11 and cell.end == 7:
                    args.append("rd")
                elif cell.start == 19 and cell.end == 15:
                    args.append("rs1")
                elif cell.start == 24 and cell.end == 20:
                    args.append("rs2")
                elif cell.start == 31 and cell.end == 27:
                    args.append("rs3")
                elif cell.name == "aq":
                    args.append("aq")
                elif cell.name == "rl":
                    args.append("rl")
                else:
                    name = cell.name if cell.name else "imm"
                    name = name.replace("{", "").replace("}", "").replace("=", "_").replace("≠", "_neq_").split("[")[0]
                    args.append(name)

        # Fixed bits usually MSB to LSB
        cells_descending = sorted(insn.cells, key=lambda c: c.start, reverse=True)
        for cell in cells_descending:
            if cell.is_fixed:
                val = int(cell.bit_str, 2)
                if cell.start == 6 and cell.end == 0:
                    fixed.append(f"6..2=0x{(val >> 2) & 0x1F:02X}")
                    fixed.append(f"1..0={val & 0x3}")
                elif cell.start == 14 and cell.end == 12:
                    fixed.append(f"14..12={val}")
                else:
                    fixed.append(f"{cell.start}..{cell.end}=0x{val:X}")

        name_str = insn.name.lower().replace(".", "_").ljust(15)
        args_str = " ".join(args).ljust(25)
        fixed_str = " ".join(fixed)
        print(f"{name_str} {args_str} {fixed_str}")

if __name__ == "__main__":
    generate_riscv_opcodes()
