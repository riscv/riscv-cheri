#!/usr/bin/env python3

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
                    outStr += '|' + insn_xref(row[i])
                else:
                    outStr += '|'+row[i]
            self.file.write(outStr+'\n')

    def check(self,row):
        return row[self.header.index("Zabhlrsc")] == "✔"

class rvyi_ext_name_insns(table):
    cols = ["Mnemonic", "{rvyi_ext_name}", "{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
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
        return row[self.header.index("{rvyi_ext_name}")] == "✔"

class rvyi_sentry_ext_name_insns(table):
    cols = ["Mnemonic", "{rvyi_sentry_ext_name}", "{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
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
        return row[self.header.index("{rvyi_sentry_ext_name}")] == "✔"

class rvyi_mod_ext_name_insns(table):
    cols = ["Mnemonic", "{rvyi_mod_ext_name}", "{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
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
        return row[self.header.index("{rvyi_mod_ext_name}")] == "✔"

class rvyc_ext_name_insns(table):
    cols = ["Mnemonic", "{rvyc_ext_name}", "{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
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
        return row[self.header.index("{rvyc_ext_name}")] == "✔"

class rvyc_mod_ext_name_insns(table):
    cols = ["Mnemonic", "{rvyc_mod_ext_name}", "{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
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
        return row[self.header.index("{rvyc_mod_ext_name}")] == "✔"

class rvyba_ext_name_insns(table):
    cols = ["Mnemonic", "{rvyba_ext_name}", "{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
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
        return row[self.header.index("{rvyba_ext_name}")] == "✔"

class rvya_ext_name_insns(table):
    cols = ["Mnemonic", "{rvya_ext_name}", "{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
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
        return row[self.header.index("{rvya_ext_name}")] == "✔"

class rvyalrsc_ext_name_insns(table):
    cols = ["Mnemonic", "{rvyalrsc_ext_name}", "{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
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
        return row[self.header.index("{rvyalrsc_ext_name}")] == "✔"

class rvyaamo_ext_name_insns(table):
    cols = ["Mnemonic", "{rvyaamo_ext_name}", "{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
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
        return row[self.header.index("{rvyaamo_ext_name}")] == "✔"

class rvyh_ext_name_insns(table):
    cols = ["Mnemonic", "{rvyh_ext_name}", "{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
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
        return row[self.header.index("{rvyh_ext_name}")] == "✔"

class rvycbom_ext_name_insns(table):
    cols = ["Mnemonic", "{rvycbom_ext_name}", "{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
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
        return row[self.header.index("{rvycbom_ext_name}")] == "✔"

class rvycboz_ext_name_insns(table):
    cols = ["Mnemonic", "{rvycboz_ext_name}", "{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
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
        return row[self.header.index("{rvycboz_ext_name}")] == "✔"

class rvycbop_ext_name_insns(table):
    cols = ["Mnemonic", "{rvycbop_ext_name}", "{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
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
        return row[self.header.index("{rvycbop_ext_name}")] == "✔"

class hybrid_ext_name_insns(table):
    cols = ["Mnemonic", "{rvyi_default_ext_name}", "{cheri_base32_ext_name}", "{cheri_base64_ext_name}", "Function"]
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
        return row[self.header.index("{rvyi_default_ext_name}")] == "✔"

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

if __name__ == "__main__":
    args = parse_cmdline_args()

    if os.path.exists(args.output_dir) == 0:
      os.mkdir(args.output_dir)

    with open(args.csr,newline='') as csrFile:
        reader = csv.reader(csrFile, delimiter=',')
        header = next(reader)
        tables = []

        tables.append(csr_alias_action          (os.path.join(args.output_dir, "csr_alias_action_table_body.adoc"),header))
        tables.append(csr_new_write_action      (os.path.join(args.output_dir, "new_csr_write_action_table_body.adoc"),header))
        tables.append(csr_aliases               (os.path.join(args.output_dir, "csr_aliases_table_body.adoc"),header))
        tables.append(csr_renamed_purecap_mode_d(os.path.join(args.output_dir, "csr_renamed_purecap_mode_d_table_body.adoc"),header))
        tables.append(csr_renamed_purecap_mode_m(os.path.join(args.output_dir, "csr_renamed_purecap_mode_m_table_body.adoc"),header))
        tables.append(csr_renamed_purecap_mode_s(os.path.join(args.output_dir, "csr_renamed_purecap_mode_s_table_body.adoc"),header))
        tables.append(csr_renamed_purecap_mode_vs(os.path.join(args.output_dir, "csr_renamed_purecap_mode_vs_table_body.adoc"),header))
        tables.append(csr_renamed_purecap_mode_u(os.path.join(args.output_dir, "csr_renamed_purecap_mode_u_table_body.adoc"),header))
        #maybe these should be included but they're not
        #tables.append(csr_added_purecap_mode_d  (os.path.join(args.output_dir, "csr_added_purecap_mode_d_table_body.adoc"),header))
        #tables.append(csr_added_purecap_mode_m  (os.path.join(args.output_dir, "csr_added_purecap_mode_m_table_body.adoc"),header))
        #tables.append(csr_added_purecap_mode_s  (os.path.join(args.output_dir, "csr_added_purecap_mode_s_table_body.adoc"),header))
        tables.append(csr_added_legacy          (os.path.join(args.output_dir, "csr_added_hybrid_table_body.adoc"),header))
        tables.append(csr_perms                 (os.path.join(args.output_dir, "csr_permission_table_body.adoc"),header))
        tables.append(csr_exevectors            (os.path.join(args.output_dir, "csr_exevectors_table_body.adoc"),header))

        for row in reader:
            for t in tables:
                t.update(row)

    with open(args.isa,newline='') as isaFile:
        reader = csv.reader(isaFile, delimiter=',')
        header = next(reader)
        tables = []

        #same for rv32/rv64
        tables.append(Zabhlrsc_insns               (os.path.join(args.output_dir, "Zabhlrsc_insns_table_body.adoc"), header))
        tables.append(rvyalrsc_ext_name_insns      (os.path.join(args.output_dir, "RVYALRSC_insns_table_body.adoc"), header))
        tables.append(rvyaamo_ext_name_insns       (os.path.join(args.output_dir, "RVYAAMO_insns_table_body.adoc"), header))
        tables.append(rvyh_ext_name_insns          (os.path.join(args.output_dir, "RVYH_insns_table_body.adoc"), header))
        tables.append(rvyi_ext_name_insns          (os.path.join(args.output_dir, "RVYI_insns_table_body.adoc"), header))
        tables.append(rvyi_sentry_ext_name_insns   (os.path.join(args.output_dir, "RVYI_SENTRY_insns_table_body.adoc"), header))
        tables.append(rvyi_mod_ext_name_insns      (os.path.join(args.output_dir, "RVYI_MOD_insns_table_body.adoc"), header))
        tables.append(rvyc_ext_name_insns          (os.path.join(args.output_dir, "RVYC_insns_table_body.adoc"), header))
        tables.append(rvyc_mod_ext_name_insns      (os.path.join(args.output_dir, "RVYC_MOD_insns_table_body.adoc"), header))
        tables.append(rvyba_ext_name_insns         (os.path.join(args.output_dir, "RVYBA_insns_table_body.adoc"), header))
        tables.append(rvycbom_ext_name_insns       (os.path.join(args.output_dir, "RVYCBOM_insns_table_body.adoc"), header))
        tables.append(rvycboz_ext_name_insns       (os.path.join(args.output_dir, "RVYCBOZ_insns_table_body.adoc"), header))
        tables.append(rvycbop_ext_name_insns       (os.path.join(args.output_dir, "RVYCBOP_insns_table_body.adoc"), header))
        tables.append(hybrid_ext_name_insns        (os.path.join(args.output_dir, "ZyhybridI_insns_table_body.adoc"), header))
        tables.append(illegal_insns                (os.path.join(args.output_dir, "illegal_insns_table_body.adoc"), header))

        for row in reader:
            for t in tables:
                t.update(row)
