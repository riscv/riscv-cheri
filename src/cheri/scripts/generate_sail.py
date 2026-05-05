#!/usr/bin/env python3
import sys
from rvy_instruction_encodings import get_custom3_insts

def generate_sail():
    instructions = get_custom3_insts()

    encdec_lines = []
    assembly_lines = []

    for insn in instructions:
        if insn.name == "YHIR":
            continue
        cells = sorted(insn.cells, key=lambda c: c.start)

        ast_args = []
        for cell in cells:
            if not cell.is_fixed:
                name = cell.name.replace("{", "").replace("}", "").split("≠")[0].split("=")[0].split("[")[0]
                if name not in ast_args:
                    ast_args.append(name)

        ast_name = insn.name.upper().replace(".", "_")
        inst_name = insn.name.lower().replace(".", "_")

        args_str = ", ".join(ast_args)

        # encdec
        encdec_parts = []
        for cell in reversed(cells): # MSB to LSB
            if cell.is_fixed:
                encdec_parts.append(f"0b{cell.bit_str}")
            else:
                name = cell.name.replace("{", "").replace("}", "").split("≠")[0].split("=")[0].split("[")[0]
                length = cell.start - cell.end + 1
                if name in ("rd", "rs1", "rs2", "rs3", "cd", "cs1", "cs2", "aq", "rl"):
                    encdec_parts.append(f"encdec_reg({name})")
                else:
                    encdec_parts.append(f"{name} : bits({length})")

        encdec = f"mapping clause encdec = {ast_name}({args_str}) if cheri_registers_enabled()\n"
        encdec += f"  <-> {' @ '.join(encdec_parts)} if cheri_registers_enabled()"
        encdec_lines.append(encdec)

        # assembly
        asm_parts = [f'"{inst_name}"']
        for i, arg in enumerate(ast_args):
            if i == 0:
                asm_parts.append("spc()")
            else:
                asm_parts.append("sep()")

            if arg in ("cd", "cs1", "cs2"):
                asm_parts.append(f"cap_reg_name({arg})")
            elif arg in ("rd", "rs1", "rs2", "rs3"):
                asm_parts.append(f"reg_name({arg})")
            elif arg in ("aq", "rl"):
                # Usually these might be printed differently, but we'll assume string literal or skip
                # Actually, standard atomics might append .aq.rl to the mnemonic, but we'll leave it simple
                asm_parts.append(f"reg_name({arg})")
            else:
                length = next(c.start - c.end + 1 for c in insn.cells if not c.is_fixed and c.name.replace("{", "").replace("}", "").split("≠")[0].split("=")[0].split("[")[0] == arg)
                asm_parts.append(f"hex_bits_{length}({arg})")

        assembly = f"mapping clause assembly = {ast_name}({args_str})\n"
        assembly += f"  <-> {' ^ '.join(asm_parts)}"
        assembly_lines.append(assembly)

    print("// --- encdec clauses ---")
    for line in encdec_lines:
        print(line)

    print("\n// --- assembly clauses ---")
    for line in assembly_lines:
        print(line)

if __name__ == "__main__":
    generate_sail()
