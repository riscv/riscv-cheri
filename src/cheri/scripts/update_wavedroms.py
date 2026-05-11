#!/usr/bin/env python3
"""Script to update Wavedrom diagrams embedded in Asciidoc files."""
import argparse
import difflib
import glob
import os
import re
import sys
from typing import Dict, List, Set

from rvy_instruction_encodings import get_custom3_insts, Instruction, get_macro_to_insn_mapping, MajorOpcode

_WARNING_TEXT = "WARNING: The instruction encoding is not final and is highly likely to change prior to v1.0"
_WARNING_BLOCK = f"\n\n{_WARNING_TEXT}\n"
_WAVEDROM_PATTERN = re.compile(
    r"(\[wavedrom[^\n]*\]\n\.\.\.\.\n)(\{reg:\s*\[.*?\]\})(\n\.\.\.\.)(" + re.escape(_WARNING_BLOCK) + ")?",
    flags=re.DOTALL
)


def _process_wavedrom_block(
    block: str,
    prefix: str,
    content: str,
    suffix: str,
    basename: str,
    old_to_new: Dict[str, str],
    insn_map: Dict[str, Instruction],
    generated_insns: Set[Instruction]
) -> tuple[str, bool]:
    """Process a single wavedrom block and return the updated content."""
    used_macros = sorted(list(set(re.findall(r"\{([A-Z0-9_]+)\}", block))))
    target_insns: List[Instruction] = []

    for macro in used_macros:
        new_name = old_to_new.get(macro)
        if new_name and new_name in insn_map:
            target_insns.append(insn_map[new_name])

    if basename == "CMV" and target_insns and target_insns[0].name.startswith("YADD"):
        # cmv.adoc uses {CADD} macro instead of {CMV} in the original file
        target_insns = []
    elif basename == "GCHI" and "YHIR" in insn_map:
        target_insns = [insn_map["YHIR"]]
    elif basename == "MODESW_32BIT" and "YMODESWY" in insn_map and "YMODESWI" in insn_map:
        target_insns = [insn_map["YMODESWY"], insn_map["YMODESWI"]]

    if not target_insns:
        if basename in old_to_new and old_to_new[basename] in insn_map:
            target_insns = [insn_map[old_to_new[basename]]]
        elif basename == "AMOSWAP_CAP" and "AMOSWAP.Y" in insn_map:
            target_insns = [insn_map["AMOSWAP.Y"]]
        elif basename == "LOAD_RES_CAP" and "LR.Y" in insn_map:
            target_insns = [insn_map["LR.Y"]]
        elif basename == "STORE_COND_CAP" and "SC.Y" in insn_map:
            target_insns = [insn_map["SC.Y"]]
        elif basename == "STORECAP" and "SY" in insn_map:
            target_insns = [insn_map["SY"]]

    if not target_insns:
        return prefix + content + suffix, False

    for insn in target_insns:
        generated_insns.add(insn)

    should_warn = any(insn.op.val in (MajorOpcode.RVY_A, MajorOpcode.RVY_B) for insn in target_insns)
    return prefix + "\n".join(Instruction.as_merged_wavedrom(target_insns)) + suffix, should_warn


def update_wavedrom_files(pretend: bool = False):
    """Update all wavedrom files with the latest instruction encodings."""
    old_to_new = get_macro_to_insn_mapping()
    instructions = list(get_custom3_insts())
    insn_map = {}

    for insn in instructions:
        base_name = insn.name.split()[0]
        for part in base_name.split("/"):
            insn_map[part] = insn

    wavedrom_files = glob.glob("src/cheri/insns/**/*.adoc", recursive=True)
    generated_insns: Set[Instruction] = set()

    for filename in wavedrom_files:
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read()

        basename = os.path.basename(filename).replace(".adoc", "").upper()

        def _replace_wrapper(match: re.Match) -> str:
            new_block, should_warn = _process_wavedrom_block(
                match.group(0), match.group(1), match.group(2), match.group(3), basename, old_to_new, insn_map, generated_insns
            )

            if should_warn:
                return new_block + _WARNING_BLOCK
            else:
                return new_block

        new_content = _WAVEDROM_PATTERN.sub(_replace_wrapper, content)

        if new_content != content:
            if pretend:
                diff = difflib.unified_diff(
                    content.splitlines(keepends=True),
                    new_content.splitlines(keepends=True),
                    fromfile=filename,
                    tofile=filename,
                )
                sys.stdout.writelines(diff)
            else:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(new_content)
                print(f"Updated {filename}")
        else:
            if not _WAVEDROM_PATTERN.search(content):
                print(f"no wavedrom in {filename}")
            else:
                print(f"Contents {filename} already correct")
                if pretend:
                    for match in _WAVEDROM_PATTERN.finditer(content):
                        print(match.group(0))

    missing_files = []
    for insn in instructions:
        if "(std)" in insn.name or "UNALLOCATED" in insn.name or "RESERVED" in insn.name or "STANDARD" in insn.name:
            continue
        if insn not in generated_insns:
            missing_files.append(insn.name)

    if missing_files:
        print(
            f"Warning: Missed generating wavedroms for the following instructions (files might be missing): {', '.join(missing_files)}",
            file=sys.stderr,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Update embedded Wavedrom diagrams.")
    parser.add_argument(
        "--in-place",
        action="store_false",
        dest="pretend",
        default=True,
        help="Actually update files instead of printing diff",
    )
    parser.add_argument(
        "--pretend",
        action="store_true",
        dest="pretend",
        help="Print diff instead of updating files (default)",
    )
    args = parser.parse_args()
    update_wavedrom_files(pretend=args.pretend)
