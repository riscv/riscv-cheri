#!/usr/bin/env python3

import abc
import os
import shutil
import csv
import argparse

remapped_isns = {
    'CBO.ZERO': 'CBO_ZERO_CHERI',
    'CBO.INVAL': 'CBO_INVAL_CHERI',
    'CBO.CLEAN': 'CBO_CLEAN_CHERI',
    'CBO.FLUSH': 'CBO_FLUSH_CHERI',
    'PREFETCH.R': 'PREFETCH_R_CHERI',
    'PREFETCH.W': 'PREFETCH_W_CHERI',
    'PREFETCH.I': 'PREFETCH_I_CHERI',
    'SH1ADD': 'SH1ADD_CHERI',
    'SH2ADD': 'SH2ADD_CHERI',
    'SH3ADD': 'SH3ADD_CHERI',
    'MRET': 'MRET_CHERI',
    'SRET': 'SRET_CHERI',
}

def insn_xref(insn: str):
    custom_xref = remapped_isns.get(insn)
    if custom_xref is not None:
        return f'<<{custom_xref},{insn}>>'
    return f'<<{insn}>>'


class table(abc.ABC):
    """
    virtual class used to define each table
    """
    filename = ""
    file = ""
    header: list[str]

    def __init__(self, filename, header: list[str]):
        self.filename = filename
        if os.path.exists(self.filename):
            os.remove(self.filename)
        self.file = open(self.filename, 'w')
        self.header = header

    def __del__(self):
        self.file.close()

    @abc.abstractmethod
    def update(self, row: list[str]): ...


class InsnTable(table):
    """
    Base class for instruction tables that check for a '✔' in a specific column
    """
    indices: list[int]
    other_cols: list[str]
    check_col: str

    def __init__(self, check_col: str, filename: str, header: list[str], other_cols: list[str] = None):
        super().__init__(filename, header)
        self.check_col = check_col
        if other_cols is None:
            other_cols = ["{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
        self.other_cols = other_cols
        self.check_index = self.header.index(self.check_col)
        self.indices = [self.header.index(col) for col in self.other_cols]
        self.mnemonic_col_idx = self.header.index("Mnemonic")

        self.file.write('|' + '|'.join(["Mnemonic", *self.other_cols]) + '\n')

    def update(self, row: list[str]):
        if self.check(row):
            outStr = '|' + insn_xref(row[self.mnemonic_col_idx])
            for i in self.indices:
               outStr += '|' + row[i]
            self.file.write(outStr + '\n')

    def check(self, row: list[str]):
        return row[self.check_index] == "✔"


class illegal_insns(table):
    cols = ["Mnemonic", "illegal insn if (1)", "OR illegal insn if (2)", "OR illegal insn if (3)"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(self.cols)+'\n')
        self.indices=[]
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            outStr = ""
            for i in self.indices:
                if i==0:
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("illegal insn if (1)")] != ""

class csr_aliases(table):
    cols = ["YLEN CSR", "Alias", "Prerequisites"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(self.cols)+'\n')
        self.indices=[]
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            outStr = ""
            for i in self.indices:
                if i<=2:
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != ""

def resolve_col_display_name(col_name):
    col_display_names = {
        "YLEN CSR": "{cheri_base_ext_name} CSR",
        "Alias":    "Extended CSR"
    }

    return col_display_names[col_name] if col_name in col_display_names else col_name

class csr_renamed_purecap_mode_d(table):
    cols = ["YLEN CSR", "Address", "Alias", "Prerequisites", "Permissions", "Description"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(map(resolve_col_display_name, self.cols))+'\n')
        self.indices=[]
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            outStr = ""
            for i in self.indices:
                if i==0 or i==2:
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != "" and row[self.header.index("Mode")] == "D"

class csr_added_legacy(table):
    cols = ["YLEN CSR", "Address", "Prerequisites", "Permissions", "Description"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(self.cols)+'\n')
        self.indices=[]
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            outStr = ""
            for i in self.indices:
                if i==0 or i==2:
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] == "" and "{cheri_default_ext_name}" == row[self.header.index("Prerequisites")].strip()

class csr_added_purecap_mode_d(table):
    cols = ["YLEN CSR", "Address", "Prerequisites", "Permissions", "Description"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(self.cols)+'\n')
        self.indices=[]
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            outStr = ""
            for i in self.indices:
                if i==0:
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] == "" and row[self.header.index("Mode")] == "D"


class csr_renamed_purecap_mode_m(table):
    cols = ["YLEN CSR", "Address", "Alias", "Prerequisites", "Permissions", "Description"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(map(resolve_col_display_name, self.cols))+'\n')
        self.indices=[]
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            outStr = ""
            for i in self.indices:
                if i==0 or i==2:
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != "" and row[self.header.index("Mode")] == "M"

class csr_added_purecap_mode_m(table):
    cols = ["YLEN CSR", "Address", "Prerequisites", "Permissions", "Description"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(self.cols)+'\n')
        self.indices=[]
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            outStr = ""
            for i in self.indices:
                if i==0 or i==2:
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] == "" and row[self.header.index("Mode")] == "M"

class csr_renamed_purecap_mode_s(table):
    cols = ["YLEN CSR", "Address", "Alias", "Prerequisites", "Permissions", "Description"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(map(resolve_col_display_name, self.cols))+'\n')
        self.indices=[]
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            outStr = ""
            for i in self.indices:
                if i==0 or i==2:
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != "" and row[self.header.index("Mode")] == "S"

class csr_renamed_purecap_mode_vs(table):
    cols = ["YLEN CSR", "Address", "Alias", "Prerequisites", "Permissions", "Description"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(map(resolve_col_display_name, self.cols))+'\n')
        self.indices=[]
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            outStr = ""
            for i in self.indices:
                if i==0 or i==2:
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != "" and row[self.header.index("Mode")] == "VS"

class csr_added_purecap_mode_s(table):
    cols = ["YLEN CSR", "Address", "Prerequisites", "Permissions", "Description"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(self.cols)+'\n')
        self.indices=[]
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            outStr = ""
            for i in self.indices:
                if i==0 or i==2:
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] == "" and row[self.header.index("Mode")] == "S"

class csr_renamed_purecap_mode_u(table):
    cols = ["YLEN CSR", "Address", "Alias", "Prerequisites", "Permissions", "Description"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(map(resolve_col_display_name, self.cols))+'\n')
        self.indices=[]
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            outStr = ""
            for i in self.indices:
                if i==0 or i==2:
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != "" and row[self.header.index("Mode")] == "U"

class csr_alias_action(table):
    cols = ["YLEN CSR", "Action on XLEN write", "Action on YLEN write"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(self.cols)+'\n')
        self.indices=[]
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            outStr = ""
            for i in self.indices:
                if i<2:
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != ""

class csr_new_write_action(csr_alias_action):
    def check(self,row):
        return row[self.header.index("Alias")] == ""

class csr_perms(table):
    cols = ["YLEN CSR", "Prerequisites", "Address", "Permissions", "Reset Value", "Description"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(self.cols)+'\n')
        self.indices=[]
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            outStr = ""
            for i in self.indices:
                if i==0:
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("YLEN CSR")] != ""

class csr_exevectors(table):
    cols = ["YLEN CSR", "Code Pointer", "Data Pointer", "Unseal On Execution"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(self.cols)+'\n')
        self.indices=[]
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            outStr = ""
            for i in self.indices:
                if i==0:
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Code Pointer")] == "✔" or \
            row[self.header.index("Unseal On Execution")] == "✔" or \
            row[self.header.index("Data Pointer")] == "✔"

def parse_cmdline_args():
    parser = argparse.ArgumentParser(description="Generate tables for CHERI ISA specification")

    parser.add_argument("--output-dir", "-o", metavar="DIR", type=str, help="Output directory where generated files are written")
    parser.add_argument("--csr", metavar="CSV", type=str, help="Input CSV file with list of CSRs")
    parser.add_argument("--isa", metavar="CSV", type=str, help="Input CSV file with list of instructions")

    return parser.parse_args()

def output_file(args, filename: str) -> str:
    return os.path.join(args.output_dir, filename)


if __name__ == "__main__":
    args = parse_cmdline_args()

    if os.path.exists(args.output_dir) == 0:
      os.mkdir(args.output_dir)

    with open(args.csr,newline='') as csrFile:
        reader = csv.reader(csrFile, delimiter=',')
        header = next(reader)
        tables = []

        tables.append(csr_alias_action          (output_file(args, "csr_alias_action_table_body.adoc"),header))
        tables.append(csr_new_write_action      (output_file(args, "new_csr_write_action_table_body.adoc"),header))
        tables.append(csr_aliases               (output_file(args, "csr_aliases_table_body.adoc"),header))
        tables.append(csr_renamed_purecap_mode_d(output_file(args, "csr_renamed_purecap_mode_d_table_body.adoc"),header))
        tables.append(csr_renamed_purecap_mode_m(output_file(args, "csr_renamed_purecap_mode_m_table_body.adoc"),header))
        tables.append(csr_renamed_purecap_mode_s(output_file(args, "csr_renamed_purecap_mode_s_table_body.adoc"),header))
        tables.append(csr_renamed_purecap_mode_vs(output_file(args, "csr_renamed_purecap_mode_vs_table_body.adoc"),header))
        tables.append(csr_renamed_purecap_mode_u(output_file(args, "csr_renamed_purecap_mode_u_table_body.adoc"),header))
        #maybe these should be included but they're not
        #tables.append(csr_added_purecap_mode_d  (output_file(args, "csr_added_purecap_mode_d_table_body.adoc"),header))
        #tables.append(csr_added_purecap_mode_m  (output_file(args, "csr_added_purecap_mode_m_table_body.adoc"),header))
        #tables.append(csr_added_purecap_mode_s  (output_file(args, "csr_added_purecap_mode_s_table_body.adoc"),header))
        tables.append(csr_added_legacy          (output_file(args, "csr_added_hybrid_table_body.adoc"),header))
        tables.append(csr_perms                 (output_file(args, "csr_permission_table_body.adoc"),header))
        tables.append(csr_exevectors            (output_file(args, "csr_exevectors_table_body.adoc"),header))

        for row in reader:
            for t in tables:
                t.update(row)

    with open(args.isa,newline='') as isaFile:
        reader = csv.reader(isaFile, delimiter=',')
        header = next(reader)
        tables = [
            InsnTable(
                check_col="Zabhlrsc",
                filename=output_file(args,  "Zabhlrsc_insns_table_body.adoc"),
                header=header,
                other_cols=["Function"],
            ),
            InsnTable(
                check_col="{cheri_base_ext_name}",
                filename=output_file(args, "RVY_insns_table_body.adoc"),
                header=header,
            ),
            InsnTable(
                check_col="{rvy_sentry_ext_name}",
                filename=output_file(args,  "Zys_insns_table_body.adoc"),
                header=header,
            ),
            InsnTable(
                check_col="{rvy_i_mod_ext_name}",
                filename=output_file(args,  "RVY_I_mod_insns_table_body.adoc"),
                header=header,
            ),
            InsnTable(
                check_col="{rvy_zca_ext_name}",
                filename=output_file(args, "RVY_Zca_insns_table_body.adoc"),
                header=header,
            ),
            InsnTable(
                check_col="{rvy_zca_mod_ext_name}",
                filename=output_file(args,  "RVY_Zca_mod_insns_table_body.adoc"),
                header=header,
            ),
            InsnTable(
                check_col="{rvy_zba_ext_name}",
                filename=output_file(args, "RVY_Zba_insns_table_body.adoc"),
                header=header,
            ),
            InsnTable(
                check_col="{rvy_zalrsc_ext_name}",
                filename=output_file(args,  "RVY_Zalrsc_insns_table_body.adoc"),
                header=header,
            ),
            InsnTable(
                check_col="{rvy_zaamo_ext_name}",
                filename=output_file(args,  "RVY_Zaamo_insns_table_body.adoc"),
                header=header,
            ),
            InsnTable(
                check_col="{rvy_h_ext_name}",
                filename=output_file(args, "RVY_H_insns_table_body.adoc"),
                header=header,
            ),
            InsnTable(
                check_col="{rvy_zicbom_mod_ext_name}",
                filename=output_file(args,  "RVY_Zicbom_mod_insns_table_body.adoc"),
                header=header,
            ),
            InsnTable(
                check_col="{rvy_zicboz_mod_ext_name}",
                filename=output_file(args,  "RVY_Zicboz_mod_insns_table_body.adoc"),
                header=header,
            ),
            InsnTable(
                check_col="{rvy_zicbop_mod_ext_name}",
                filename=output_file(args,  "RVY_Zicbop_mod_insns_table_body.adoc"),
                header=header,
            ),
            InsnTable(
                check_col="{cheri_default_ext_name}",
                filename=output_file(args,  "Zyhybrid_insns_table_body.adoc"),
                header=header,
            ),
            illegal_insns(
                filename=output_file(args, "illegal_insns_table_body.adoc"),
                header=header,
            ),
        ]
        for row in reader:
            for t in tables:
                t.update(row)
