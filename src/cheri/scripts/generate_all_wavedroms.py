#!/usr/bin/env python3
## WARNING: This script is almost entirely AI generated. The output looks correct, but this code might not be
import sys
import os
import argparse

# Add the current directory to sys.path to allow importing from rvy_instruction_encodings
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from rvy_instruction_encodings import get_custom3_insts, RVYInstructions, Instruction


def get_sections(rvy_insts: RVYInstructions) -> list[tuple[str, list[Instruction]]]:
    return [
        ("3OP", rvy_insts.regular_3op_insns),
        ("2OP", rvy_insts.regular_2op_insns),
        ("YADDI/LY/SY", [rvy_insts.yaddi, rvy_insts.ly, rvy_insts.sy]),
        ("AMO", rvy_insts.amo_insns),
        ("MISC", rvy_insts.misc_insns),
    ]


def generate_overview(rvy_insts, section_gen_func):
    lines = []
    for title, insts in get_sections(rvy_insts):
        if not insts:
            continue

        lines.append(f"=== {title} Instruction Encodings")
        lines.append("")
        lines.extend(section_gen_func(title, insts))
        lines.append("")
    return lines


def generate_bytefield_section(title, insts) -> list[str]:
    lines = ["[bytefield,subs=attributes+]", "...."]
    lines.append('(defattrs :plain [:plain {:font-family "M+ 1p Fallback" :font-size 20}])')
    lines.append("(def row-height 40)")
    lines.append("(def boxes-per-row 40)")
    lines.append(
        '(draw-column-headers {:height 20 :font-size 18 :labels (concat (reverse (map str (range 32))) (repeat 8 ""))})'
    )

    for i, insn in enumerate(insts):
        insn_cells = sorted(insn.cells, key=lambda c: c.end, reverse=True)

        for c in insn_cells:
            span = c.start - c.end + 1
            val = c.value_for_encoding_overview
            lines.append(f'(draw-box "{val}" {{:span {span}}})')

        lines.append(f'(draw-box "{insn.name}" {{:span 8 :borders {{}}}})')

        if i < len(insts) - 1:
            lines.append("(next-row)")

    lines.append("....")
    return lines


def generate_asciidoc_table_section(title, insts) -> list[str]:
    lines = []
    span_map = {
        (31, 25): "4+^|",
        (24, 20): "2+^|",
        (31, 27): "2+^|",
        (26, 26): "^|",
        (25, 25): "^|",
        (31, 20): "6+^|",
        (26, 20): "4+^|",
        (31, 29): "^|",
        (28, 20): "5+^|",
        (19, 15): "2+^|",
        (14, 12): "2+^|",
        (11, 7): "2+^|",
        (6, 0): "2+^|",
    }

    lines.extend(
        [
            '[%autowidth.stretch,float="center",align="center",cols="^2m,^2m,^2m,^2m,<2m,>3m, <4m, >4m, <4m, >4m, <4m, >4m, <4m, >4m, <6m"]',
            "|===",
        ]
    )

    lines.append(f"15+^|*{title} Instruction Encodings*")

    if title == "AMO":
        lines.append(" 2+^|31:27 ^|26 ^|25  2+^|24:20  2+^|19:15  2+^|14:12  2+^|11:7  2+^|6:0 | Inst")
    elif title == "MISC":
        lines.append(" ^|31:29 ^|28:27  4+^|26:20  2+^|19:15  2+^|14:12  2+^|11:7  2+^|6:0 | Inst")
    else:
        lines.append(" 4+^|31:25  2+^|24:20  2+^|19:15  2+^|14:12  2+^|11:7  2+^|6:0 | Inst")

    for insn in insts:
        insn_cells = sorted(insn.cells, key=lambda c: c.end, reverse=True)
        row = []

        for c in insn_cells:
            val = c.value_for_encoding_overview
            span = span_map.get((c.start, c.end), "^|")

            # Special cases for MISC to align with the split header
            if title == "MISC":
                if c.start == 31 and c.end == 27:
                    span = "2+^|"  # Spans 31:29 and 28:27
                elif c.start == 26 and c.end == 20:
                    span = "4+^|"  # Spans 26:20
                elif c.start == 31 and c.end == 29:
                    span = "^|"  # Spans 31:29
                elif c.start == 28 and c.end == 20:
                    span = "5+^|"  # Spans 28:27 and 26:20

            row.append(f"{span}{val}")

        # Instruction Name
        row.append(f"<|{insn.name}")

        # Join with space
        lines.append(" ".join(row))

    lines.append("|===")
    return lines


def generate_wavedrom_section(title, insts) -> list[str]:
    from rvy_instruction_encodings import Instruction
    lines = []
    if title in ("3OP", "2OP") and insts:
        lines.append(f"// {title} Instructions")
        lines.extend(Instruction.as_merged_wavedrom(insts, include_header=True, collapse_identical_labels=False))
        lines.append("")
    else:
        for insn in insts:
            lines.append(f"// {insn.name}")
            lines.extend(insn.as_wavedrom(include_header=True))
            lines.append("")
    return lines


def main():
    parser = argparse.ArgumentParser(description="Generate Wavedrom diagrams for all RVY instructions.")
    parser.add_argument(
        "-o", "--output", default="rvy_wavedroms.adoc", help="Output file (default: rvy_wavedroms.adoc)"
    )
    parser.add_argument(
        "--encoding-overview-bytefield",
        dest="encoding_overview_bytefield",
        help="Output file for encoding overview in Bytefield-svg format",
    )
    parser.add_argument("--encoding-overview-table", help="Output file for encoding overview in AsciiDoc table format")
    parser.add_argument("--encoding-overview-wavedrom", help="Output file for encoding overview in Wavedrom format")
    args = parser.parse_args()

    instructions = get_custom3_insts()
    if args.output:
        with open(args.output, "w") as f:
            for insn in instructions:
                f.write(f"// {insn.name}\n")
                f.write("\n".join(insn.as_wavedrom(include_header=True)))
                f.write("\n\n")
        print(f"Successfully generated {args.output}")

    if args.encoding_overview_bytefield:
        with open(args.encoding_overview_bytefield, "w") as f:
            f.write("\n".join(generate_overview(instructions, generate_bytefield_section)))
            f.write("\n")
        print(f"Successfully generated {args.encoding_overview_bytefield}")

    if args.encoding_overview_table:
        with open(args.encoding_overview_table, "w") as f:
            f.write("\n".join(generate_overview(instructions, generate_asciidoc_table_section)))
            f.write("\n")
        print(f"Successfully generated {args.encoding_overview_table}")

    if args.encoding_overview_wavedrom:
        with open(args.encoding_overview_wavedrom, "w") as f:
            f.write("\n".join(generate_overview(instructions, generate_wavedrom_section)))
            f.write("\n")
        print(f"Successfully generated {args.encoding_overview_wavedrom}")


if __name__ == "__main__":
    main()
