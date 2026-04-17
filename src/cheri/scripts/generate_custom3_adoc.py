#!/usr/bin/env python3
## WARNING: This script is almost entirely AI generated. The output looks correct, but this code might not be
from rvy_instruction_encodings import get_custom3_insts, Custom3Funct3, MajorOpcode, IType, AMOType


def generate_adoc():
    rvy_insts = get_custom3_insts()
    f3_map = Custom3Funct3.get_map()

    adoc = "=== 1. Funct3 Allocations\n\n"
    adoc += '[cols="^1,^3",options="header",stripes="even"]\n|===\n'
    adoc += "| funct3 | Instruction(s)\n\n"
    for i in range(8):
        adoc += f"| *{format(i, '03b')}* | {f3_map[i]}\n"
    adoc += "|===\n\n"

    adoc += "=== 2. R-Type 3-Operand (funct3=000)\n\n"
    adoc += '[cols="^1,^1,^1,^1,^1,^1,^1,^1,^1",options="header",stripes="even"]\n|===\n'
    adoc += "| funct7[6:3] \\ funct7[2:0] | 000 | 001 | 010 | 011 | 100 | 101 | 110 | 111\n\n"

    r3_grouped = {}
    for i in rvy_insts.regular_3op_insns:
        if isinstance(i.f7.val, int):
            r3_grouped.setdefault(i.f7.val, []).append(i.name)

    for r in range(16):
        row_str = f"| *{format(r, '04b')} (0x{r:X})*"
        for c in range(8):
            f7 = (r << 3) | c
            if f7 == 0x7F:
                name = "1OP/2OP"
            else:
                names = r3_grouped.get(f7, [])
                name = "/".join(names)
            row_str += f" | {name}"
        adoc += row_str + "\n"
    adoc += "|===\n\n"

    # 3. R-Type 1/2-Operand
    r2_by_f7 = {}
    for i in rvy_insts.regular_2op_insns:
        if isinstance(i.rs2.val, int) and hasattr(i, "f7") and isinstance(i.f7.val, int):
            r2_by_f7.setdefault(i.f7.val, []).append(i)

    table_num = 3
    for f7_val, r2_insts in sorted(r2_by_f7.items()):
        adoc += f"=== {table_num}. R-Type 1-Op/2-Op (funct3=000, funct7={format(f7_val, '07b')})\n"
        adoc += "_Note: The 5-bit rs2 field is split into columns rs2[4:3] and rows rs2[2:0]._\n\n"
        adoc += '[cols="^1,^1,^1,^1,^1",options="header",stripes="even"]\n|===\n'
        adoc += "| rs2[2:0] \\ rs2[4:3] | 00 | 01 | 10 | 11\n\n"

        r2_grouped = {}
        for i in r2_insts:
            r2_grouped.setdefault(i.rs2.val, []).append(i.name)

        for r in range(8):
            row_str = f"| *{format(r, '03b')}*"
            for c in range(4):
                rs2 = (c << 3) | r
                names = r2_grouped.get(rs2, [])
                name = "/".join(names)
                row_str += f" | {name}"
            adoc += row_str + "\n"
        adoc += "|===\n\n"
        table_num += 1

    adoc += f"\n== {table_num}. AMO Sub-opcode Allocations (funct3=100)\n\n"
    adoc += '[cols="^1,^1,^1,^1,^1,^1,^1,^1,^1",options="header",stripes="even"]\n|===\n'
    adoc += "| funct7[6:3] \\ funct7[2:0] | 000 | 001 | 010 | 011 | 100 | 101 | 110 | 111\n\n"

    amo_grouped = {}
    for i in rvy_insts.amo_insns:
        matching_f7s = []
        if isinstance(i, AMOType) and isinstance(i.f5_fixed.val, int):
            base_f7 = i.f5_fixed.val << 2
            for offset in range(4):
                matching_f7s.append(base_f7 + offset)
        for f7 in matching_f7s:
            amo_grouped.setdefault(f7, []).append(i.name)

    for r in range(16):
        row_str = f"| *{format(r, '04b')} (0x{r:X})*"
        for c in range(8):
            f7 = (r << 3) | c
            names = amo_grouped.get(f7, [])
            name = "/".join(names)
            row_str += f" | {name}"
        adoc += row_str + "\n"
    adoc += "|===\n"
    table_num += 1

    adoc += f"\n== {table_num}. MISC Sub-opcode Allocations (funct3=101)\n\n"
    adoc += '[cols="^1,^1,^1,^1,^1,^1,^1,^1,^1",options="header",stripes="even"]\n|===\n'
    adoc += "| funct7[6:3] \\ funct7[2:0] | 000 | 001 | 010 | 011 | 100 | 101 | 110 | 111\n\n"

    misc_grouped = {}
    misc_f3 = Custom3Funct3.MISC
    for i in rvy_insts.misc_insns:
        if i.op.val == MajorOpcode.CUSTOM_3 and i.f3.val == misc_f3:
            matching_f7s = []
            if isinstance(i, IType) and hasattr(i, "imm_high"):
                fixed_val = i.imm_high.val
                L = len(fixed_val)
                top_val = int(fixed_val, 2)
                if L <= 7:
                    shift = 7 - L
                    base_f7 = top_val << shift
                    for offset in range(1 << shift):
                        f7 = base_f7 + offset
                        if "shamt=XLEN" in i.name and f7 != 0:
                            continue
                        matching_f7s.append(f7)

            for f7 in matching_f7s:
                misc_grouped.setdefault(f7, []).append(i.name)

    for r in range(16):
        row_str = f"| *{format(r, '04b')} (0x{r:X})*"
        for c in range(8):
            f7 = (r << 3) | c
            names = misc_grouped.get(f7, [])
            name = "/".join(names)
            row_str += f" | {name}"
        adoc += row_str + "\n"
    adoc += "|===\n"

    return adoc


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", required=True, help="Output file path")
    args = parser.parse_args()

    adoc = generate_adoc()
    with open(args.output, "w") as f:
        f.write(adoc)
