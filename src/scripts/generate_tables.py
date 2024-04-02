#!/usr/bin/env python3

import os
import shutil
import csv
import argparse

class table:
    """
    virtual class used to define each table
    """
    filename = ""
    file = ""
    header = []

    def __init__(self, filename, header):

        self.filename = filename
        if os.path.exists(self.filename):
            os.remove(self.filename)
        self.file = open(self.filename, 'w')
        self.header = header

    def __del__(self):
        self.file.close()

    def update(self, row):
        pass

class Zabhlrsc_insns(table):
    cols = ["Mnemonic", "Zabhlrsc", "Function"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Zabhlrsc")] == "✔"

class Zcheri_legacy_insns(table):
    cols = ["Mnemonic", "RV32", "RV64", "A", "Zabhlrsc", "Zicbo[mpz]", "C or Zca", "Zba", "Zcb", "Zcmp", "Zcmt", "Zfh", "F", "D", "V", "Function"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        # Don't print instructions already listed by Zcheri_purecap
        return row[self.header.index("Zcheri_legacy")] == "✔" and row[self.header.index("Zcheri_purecap")] != "✔"

class Zcheri_purecap_insns(table):
    cols = ["Mnemonic", "RV32", "RV64", "A", "Zabhlrsc", "Zicbo[mpz]", "C or Zca", "Zba", "Zcb", "Zcmp", "Zcmt", "Zfh", "F", "D", "V", "Function"]
    indices = []

    def __init__(self, filename, header):
        super().__init__(filename, header)
        self.file.write('|'+'|'.join(self.cols)+'\n')
        self.indices=[]
        self.function_idx = self.header.index("Function")
        for i in self.cols:
            self.indices.append(self.header.index(i))

    def update(self, row):
        if self.check(row):
            out_str = ""
            for i in self.indices:
                cell_value = row[i]
                if i == 0:
                    cell_value = '<<' + cell_value + '>>'  # make an xref
                elif i == self.function_idx:
                    # Drop references to DDC authorization in the purecap table.
                    cell_value = cell_value.replace(" via int pointer", " via capability register")
                    cell_value = cell_value.replace(", authorise with DDC", "")
                out_str += '|' + cell_value
            self.file.write(out_str + '\n')

    def check(self,row):
        return row[self.header.index("Zcheri_legacy")] != "✔" and row[self.header.index("Zcheri_purecap")] == "✔"

class cap_mode_insns(table):
    cols = ["Mnemonic", "Zcheri_legacy", "Zcheri_purecap", "Function"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Valid Modes")] == "Capability"

class legacy_mode_insns(table):
    cols = ["Mnemonic", "Zcheri_legacy", "Zcheri_purecap", "Function"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Valid Modes")] == "Legacy"

class both_mode_insns(table):
    cols = ["Mnemonic", "Zcheri_legacy", "Zcheri_purecap", "Function"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Valid Modes")] == "Both"

class xlen_dependent_encoding_insns(table):
    cols = ["Mnemonic", "Function"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("XLEN dependent encoding")] == "✔"

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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("illegal insn if (1)")] != ""

class legacy_mnemonic_insns(table):
    cols = ["Mnemonic", "Legacy mnemonic RV32", "Legacy mnemonic RV64"]
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
                outStr += '|<<'+row[i]+'>>'
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Legacy mnemonic RV32")] != "" and row[self.header.index("Legacy mnemonic RV64")] != ""

class csr_aliases(table):
    cols = ["Extended CSR", "Alias", "Prerequisites"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != ""

class csr_removed_purecap_mode_d(table):
    cols = ["Alias", "XLEN Address", "Prerequisites", "Permissions", "Description"]
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
                if i==2:
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != "" and row[self.header.index("Mode")] == "D"

def resolve_col_display_name(col_name):
    col_display_names = {
        "Extended CSR": "{cheri_base_ext_name} CSR",
        "Alias":        "Replaced CSR",
        "CLEN Address": "Address",
        "XLEN Address": "Address",
    }

    return col_display_names[col_name] if col_name in col_display_names else col_name

class csr_replaced_purecap_mode_d(table):
    cols = ["Extended CSR", "CLEN Address", "Alias", "Prerequisites", "Permissions", "Description"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != "" and row[self.header.index("Mode")] == "D"

class csr_added_legacy(table):
    cols = ["Extended CSR", "CLEN Address", "Prerequisites", "Permissions", "Description"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] == "" and row[self.header.index("Zcheri_purecap")] == ""

class csr_added_purecap_mode_d(table):
    cols = ["Alias", "XLEN Address", "Prerequisites", "Permissions", "Description"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] == "" and row[self.header.index("Mode")] == "D"


class csr_removed_purecap_mode_m(table):
    cols = ["Alias", "XLEN Address", "Prerequisites", "Permissions", "Description"]
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
                if i==2:
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != "" and row[self.header.index("Mode")] == "M"

class csr_replaced_purecap_mode_m(table):
    cols = ["Extended CSR", "CLEN Address", "Alias", "Prerequisites", "Permissions", "Description"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != "" and row[self.header.index("Mode")] == "M"

class csr_added_purecap_mode_m(table):
    cols = ["Alias", "XLEN Address", "Prerequisites", "Permissions", "Description"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] == "" and row[self.header.index("Mode")] == "M"

class csr_removed_purecap_mode_s(table):
    cols = ["Alias", "XLEN Address", "Prerequisites", "Permissions", "Description"]
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
                if i==2:
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != "" and row[self.header.index("Mode")] == "S"

class csr_replaced_purecap_mode_s(table):
    cols = ["Extended CSR", "CLEN Address", "Alias", "Prerequisites", "Permissions", "Description"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != "" and row[self.header.index("Mode")] == "S"

class csr_added_purecap_mode_s(table):
    cols = ["Alias", "XLEN Address", "Prerequisites", "Permissions", "Description"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] == "" and row[self.header.index("Mode")] == "S"

class csr_removed_purecap_mode_u(table):
    cols = ["Alias", "XLEN Address", "Prerequisites", "Permissions", "Description"]
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
                if i==2:
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != "" and row[self.header.index("Mode")] == "U"

class csr_replaced_purecap_mode_u(table):
    cols = ["Extended CSR", "CLEN Address", "Alias", "Prerequisites", "Permissions", "Description"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != "" and row[self.header.index("Mode")] == "U"

class csr_added_purecap_mode_u(table):
    cols = ["Extended CSR", "CLEN Address", "Prerequisites", "Permissions", "Description"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] == "" and row[self.header.index("Mode")] == "U" and row[self.header.index("Zcheri_purecap")] == "✔"

class csr_alias_action(table):
    cols = ["Extended CSR", "Action on XLEN write", "Action on CLEN write"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Alias")] != ""

class csr_perms(table):
    cols = ["Extended CSR", "Zcheri_legacy", "Zcheri_purecap", "Prerequisites", "CLEN Address", "Permissions", "Reset Value", "Description"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Extended CSR")] != ""

class csr_exevectors(table):
    cols = ["Extended CSR", "Executable Vector", "Data Pointer", "Unseal On Execution"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Executable Vector")] == "✔" or \
            row[self.header.index("Unseal On Execution")] == "✔" or \
            row[self.header.index("Data Pointer")] == "✔"

class csr_metadata(table):
    cols = ["Extended CSR", "Store full metadata"]
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
                    #make an xref
                    outStr += '|<<'+row[i]+'>>'
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Store full metadata")] == "✔"

def parse_cmdline_args():
    parser = argparse.ArgumentParser(description="Generate tables for CHERI ISA specification")

    parser.add_argument("--output-dir", "-o", metavar="DIR", type=str, help="Output directory where generated files are written")
    parser.add_argument("--csr", metavar="CSV", type=str, help="Input CSV file with list of CSRs")
    parser.add_argument("--isa", metavar="CSV", type=str, help="Input CSV file with list of instructions")

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_cmdline_args()

    if os.path.exists(args.output_dir) == 0:
      os.mkdir(args.output_dir)

    with open(args.csr,newline='') as csrFile:
        reader = csv.reader(csrFile, delimiter=',')
        header = next(reader)
        tables = []

        tables.append(csr_alias_action           (os.path.join(args.output_dir, "csr_alias_action_table_body.adoc"),header))
        tables.append(csr_aliases                (os.path.join(args.output_dir, "csr_aliases_table_body.adoc"),header))
        tables.append(csr_removed_purecap_mode_d (os.path.join(args.output_dir, "csr_removed_purecap_mode_d_table_body.adoc"),header))
        tables.append(csr_removed_purecap_mode_m (os.path.join(args.output_dir, "csr_removed_purecap_mode_m_table_body.adoc"),header))
        tables.append(csr_removed_purecap_mode_s (os.path.join(args.output_dir, "csr_removed_purecap_mode_s_table_body.adoc"),header))
        tables.append(csr_removed_purecap_mode_u (os.path.join(args.output_dir, "csr_removed_purecap_mode_u_table_body.adoc"),header))
        tables.append(csr_replaced_purecap_mode_d(os.path.join(args.output_dir, "csr_replaced_purecap_mode_d_table_body.adoc"),header))
        tables.append(csr_replaced_purecap_mode_m(os.path.join(args.output_dir, "csr_replaced_purecap_mode_m_table_body.adoc"),header))
        tables.append(csr_replaced_purecap_mode_s(os.path.join(args.output_dir, "csr_replaced_purecap_mode_s_table_body.adoc"),header))
        tables.append(csr_replaced_purecap_mode_u(os.path.join(args.output_dir, "csr_replaced_purecap_mode_u_table_body.adoc"),header))
        tables.append(csr_added_purecap_mode_d   (os.path.join(args.output_dir, "csr_added_purecap_mode_d_table_body.adoc"),header))
        tables.append(csr_added_purecap_mode_m   (os.path.join(args.output_dir, "csr_added_purecap_mode_m_table_body.adoc"),header))
        tables.append(csr_added_purecap_mode_s   (os.path.join(args.output_dir, "csr_added_purecap_mode_s_table_body.adoc"),header))
        tables.append(csr_added_purecap_mode_u   (os.path.join(args.output_dir, "csr_added_purecap_mode_u_table_body.adoc"),header))
        tables.append(csr_added_legacy           (os.path.join(args.output_dir, "csr_added_legacy_table_body.adoc"),header))
        tables.append(csr_perms                  (os.path.join(args.output_dir, "csr_permission_table_body.adoc"),header))
        tables.append(csr_exevectors             (os.path.join(args.output_dir, "csr_exevectors_table_body.adoc"),header))
        tables.append(csr_metadata               (os.path.join(args.output_dir, "csr_metadata_table_body.adoc"),header))

        for row in reader:
            for t in tables:
                t.update(row)

    with open(args.isa,newline='') as isaFile:
        reader = csv.reader(isaFile, delimiter=',')
        header = next(reader)
        tables = []

        #same for rv32/rv64
        tables.append(Zabhlrsc_insns               (os.path.join(args.output_dir, "Zabhlrsc_insns_table_body.adoc"), header))
        tables.append(Zcheri_legacy_insns          (os.path.join(args.output_dir, "Zcheri_legacy_insns_table_body.adoc"), header))
        tables.append(Zcheri_purecap_insns         (os.path.join(args.output_dir, "Zcheri_purecap_insns_table_body.adoc"), header))
        tables.append(xlen_dependent_encoding_insns(os.path.join(args.output_dir, "xlen_dependent_encoding_insns_table_body.adoc"), header))
        tables.append(legacy_mnemonic_insns        (os.path.join(args.output_dir, "legacy_mnemonic_insns_table_body.adoc"), header))
        tables.append(illegal_insns                (os.path.join(args.output_dir, "illegal_insns_table_body.adoc"), header))
        tables.append(cap_mode_insns               (os.path.join(args.output_dir, "cap_mode_insns_table_body.adoc"), header))
        tables.append(legacy_mode_insns            (os.path.join(args.output_dir, "legacy_mode_insns_table_body.adoc"), header))
        tables.append(both_mode_insns              (os.path.join(args.output_dir, "both_mode_insns_table_body.adoc"), header))

        for row in reader:
            for t in tables:
                t.update(row)
