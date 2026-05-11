import pytest
import sys
import os

# Add current directory to path so we can import rvy_instruction_encodings
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from rvy_instruction_encodings import get_custom3_insts, Instruction


@pytest.fixture
def rvy_insts():
    return get_custom3_insts()


@pytest.fixture
def insn_map(rvy_insts):
    instructions = list(rvy_insts)
    return {part: insn for insn in instructions for part in insn.name.split()[0].split("/")}


def get_insn_def(name: str):
    all_insts = list(get_custom3_insts())
    return next(x for x in all_insts if x.name == name)


def test_yadd():
    inst = get_insn_def("YADD")
    expected = [
        "{reg: [",
        "  {bits:  7, name: 'opcode',     attr: ['7', 'RVY-A=1111011'],    type: 8},",
        "  {bits:  5, name: '{cd}',       attr: ['5', 'dest'],             type: 2},",
        "  {bits:  3, name: 'funct3',     attr: ['3', 'RVY-R=000'],        type: 8},",
        "  {bits:  5, name: '{cs1}',      attr: ['5', 'src'],              type: 4},",
        "  {bits:  5, name: 'rs2≠0',      attr: ['5', 'increment'],        type: 4},",
        "  {bits:  7, name: 'funct7',     attr: ['7', '{CADD}=0000011'],   type: 3},",
        "]}",
    ]
    assert inst.as_wavedrom() == expected


def test_ybaser():
    inst = get_insn_def("YBASER")
    expected = [
        "{reg: [",
        "  {bits:  7, name: 'opcode',     attr: ['7', 'RVY-A=1111011'],    type: 8},",
        "  {bits:  5, name: 'rd',         attr: ['5', 'dest'],             type: 2},",
        "  {bits:  3, name: 'funct3',     attr: ['3', 'RVY-R=000'],        type: 8},",
        "  {bits:  5, name: '{cs1}',      attr: ['5', 'src'],              type: 4},",
        "  {bits:  5, name: 'rs2',        attr: ['5', '{GCBASE}=00000'],   type: 3},",
        "  {bits:  7, name: 'funct7',     attr: ['7', 'RVY-2OP-YX=1111010'], type: 3},",
        "]}",
    ]
    assert inst.as_wavedrom() == expected


def test_yaddi(rvy_insts):
    inst = rvy_insts.yaddi
    expected = [
        "{reg: [",
        "  {bits:  7, name: 'opcode',     attr: ['7', 'RVY-A=1111011'],    type: 8},",
        "  {bits:  5, name: '{cd}',       attr: ['5', 'dest'],             type: 2},",
        "  {bits:  3, name: 'funct3',     attr: ['3', '{CADDI}=100'],      type: 8},",
        "  {bits:  5, name: '{cs1}',      attr: ['5', 'src'],              type: 4},",
        "  {bits: 12, name: 'imm[11:0]',  attr: ['12', 'imm'],             type: 4},",
        "]}",
    ]
    assert inst.as_wavedrom() == expected


def test_sy(rvy_insts):
    expected = [
        "{reg: [",
        "  {bits:  7, name: 'opcode',     attr: ['7', 'RVY-A=1111011'],    type: 8},",
        "  {bits:  5, name: 'offset[4:0]', attr: ['5', 'offset[4:0]'],      type: 4},",
        "  {bits:  3, name: 'funct3',     attr: ['3', '{STORE_CAP_NAME}=010'], type: 8},",
        "  {bits:  5, name: '{cs1}≠0',    attr: ['5', 'base'],             type: 4},",
        "  {bits:  5, name: '{cs2}',      attr: ['5', 'src'],              type: 4},",
        "  {bits:  7, name: 'offset[11:5]', attr: ['7', 'offset[11:5]'],     type: 4},",
        "]}",
    ]
    assert rvy_insts.sy.as_wavedrom() == expected


def test_ly(rvy_insts):
    expected = [
        "{reg: [",
        "  {bits:  7, name: 'opcode',     attr: ['7', 'RVY-A=1111011'],    type: 8},",
        "  {bits:  5, name: '{cd}',       attr: ['5', 'dest'],             type: 2},",
        "  {bits:  3, name: 'funct3',     attr: ['3', '{LOAD_CAP_NAME}=001'], type: 8},",
        "  {bits:  5, name: '{cs1}≠0',    attr: ['5', 'base'],             type: 4},",
        "  {bits: 12, name: 'imm[11:0]',  attr: ['12', 'offset'],          type: 4},",
        "]}",
    ]
    assert rvy_insts.ly.as_wavedrom() == expected


def test_srliy():
    inst = get_insn_def("YHIR")
    expected = [
        "{reg: [",
        "  {bits:  7, name: 'opcode',     attr: ['7', 'RVY-A=1111011'],    type: 8},",
        "  {bits:  5, name: 'rd',         attr: ['5', 'dest'],             type: 2},",
        "  {bits:  3, name: 'funct3',     attr: ['3', 'RVY-MISC=101'],     type: 8},",
        "  {bits:  5, name: '{cs1}',      attr: ['5', 'src'],              type: 4},",
        "  {bits:  7, name: 'shamt=XLEN', attr: ['7', 'shamt=XLEN'],       type: 4},",
        "  {bits:  5, name: 'funct5',     attr: ['5', '{GCHI}=00000'],     type: 3},",
        "]}",
    ]
    assert inst.as_wavedrom() == expected


def test_amoswap_y():
    inst = get_insn_def("AMOSWAP.Y")
    expected = [
        "{reg: [",
        "  {bits:  7, name: 'opcode',     attr: ['7', 'RVY-A=1111011'],    type: 8},",
        "  {bits:  5, name: '{cd}',       attr: ['5', 'rd'],               type: 2},",
        "  {bits:  3, name: 'funct3',     attr: ['3', 'RVY-AMO=011'],      type: 8},",
        "  {bits:  5, name: '{cs1}≠0',    attr: ['5', 'base'],             type: 4},",
        "  {bits:  5, name: '{cs2}',      attr: ['5', 'src'],              type: 4},",
        "  {bits:  1, name: 'rl',         attr: ['1', 'rl'],               type: 4},",
        "  {bits:  1, name: 'aq',         attr: ['1', 'aq'],               type: 4},",
        "  {bits:  5, name: 'funct5',     attr: ['5', 'SWAP=00001'],       type: 3},",
        "]}",
    ]
    assert inst.as_wavedrom() == expected


def test_ybndswi():
    inst = get_insn_def("YBNDSWI")
    expected = [
        "{reg: [",
        "  {bits:  7, name: 'opcode',     attr: ['7', 'RVY-A=1111011'],    type: 8},",
        "  {bits:  5, name: '{cd}',       attr: ['5', 'dest'],             type: 2},",
        "  {bits:  3, name: 'funct3',     attr: ['3', 'RVY-MISC=101'],     type: 8},",
        "  {bits:  5, name: '{cs1}',      attr: ['5', 'src'],              type: 4},",
        "  {bits:  9, name: 'ybndswimm[8:0]', attr: ['9', 'imm'],              type: 4},",
        "  {bits:  3, name: 'funct3',     attr: ['3', '{SCBNDSI}=111'],    type: 3},",
        "]}",
    ]
    assert inst.as_wavedrom() == expected


def test_modesw_merge(insn_map):
    # YMODESWY and YMODESWI
    insns = [insn_map["YMODESWY"], insn_map["YMODESWI"]]

    expected = [
        "{reg: [",
        "  {bits:  7, name: 'opcode',     attr: ['7', 'RVY-A=1111011'],    type: 8},",
        "  {bits:  5, name: '{cd}=x0',    attr: ['5', '{cd}=x0'],          type: 2},",
        "  {bits:  3, name: 'funct3',     attr: ['3', 'RVY-R=000'],        type: 8},",
        "  {bits:  5, name: '{cs1}=x0',   attr: ['5', '{cs1}=x0'],         type: 4},",
        "  {bits:  5, name: 'rs2',        attr: ['5', '{MODESW_CAP}=00000', '{MODESW_INT}=00001'], type: 3},",
        "  {bits:  7, name: 'funct7',     attr: ['7', '{SCMODE}=0110011'], type: 3},",
        "]}",
    ]
    assert Instruction.as_merged_wavedrom(insns) == expected


def test_shadd_merge(insn_map):
    insns = [insn_map["YSH1ADD"], insn_map["YSH2ADD"], insn_map["YSH3ADD"], insn_map["YSH4ADD"]]
    merged = "\n".join(Instruction.as_merged_wavedrom(insns))
    # funct7 differs for these
    assert "{SH1ADD_CHERI}=0000101" in merged
    assert "{SH4ADD_CHERI}=0011101" in merged
    assert (
        "['7', '{SH1ADD_CHERI}=0000101', '{SH2ADD_CHERI}=0001101', '{SH3ADD_CHERI}=0010101', '{SH4ADD_CHERI}=0011101']"
        in merged
    )


def test_ymv():
    inst = get_insn_def("YMV")
    expected = [
        "{reg: [",
        "  {bits:  7, name: 'opcode',     attr: ['7', 'RVY-A=1111011'],    type: 8},",
        "  {bits:  5, name: '{cd}',       attr: ['5', 'dest'],             type: 2},",
        "  {bits:  3, name: 'funct3',     attr: ['3', 'RVY-R=000'],        type: 8},",
        "  {bits:  5, name: '{cs1}',      attr: ['5', 'src'],              type: 4},",
        "  {bits:  5, name: 'rs2',        attr: ['5', '{CMV}: rs2=x0'],    type: 3},",
        "  {bits:  7, name: 'funct7',     attr: ['7', '{CADD}=0000011'],   type: 3},",
        "]}",
    ]
    assert inst.as_wavedrom() == expected
