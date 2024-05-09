# Makefile for RISC-V specification for CHERI extensions
#
# This work is licensed under the Creative Commons Attribution-ShareAlike 4.0
# International License. To view a copy of this license, visit
# http://creativecommons.org/licenses/by-sa/4.0/ or send a letter to
# Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.
#
# SPDX-License-Identifier: CC-BY-SA-4.0
#
# Description:
#
# This Makefile is designed to automate the process of building and packaging
# the specification document.

# Tools
DOCKER_IMAGE = riscvintl/riscv-docs-base-container-image:latest
GEN_SCRIPT   = $(SCRIPTS_DIR)/generate_tables.py

# Version and date
DATE    ?= $(shell date +%Y-%m-%d)
VERSION ?= v0.8.2
REVMARK ?= Draft

# URLs for downloaded CSV files
URL_BASE = https://docs.google.com/spreadsheets/d/1nyxKamsYZaeTyG8qP-JX4_oQwcuQ_4nZ_Ihm3RK0NEY/gviz/tq?tqx=out:csv
URL_ISA  = $(URL_BASE)&gid=0
URL_CSR  = $(URL_BASE)&gid=1927549494

# Directories and files
BUILD_DIR   = build
SRC_DIR     = src
SRCS        = $(wildcard $(SRC_DIR)/*.adoc)     \
              $(wildcard $(SRC_DIR)/*/*.adoc)   \
              $(wildcard $(SRC_DIR)/*/*.bib)    \
              $(wildcard $(SRC_DIR)/*/*/*.adoc) \
              $(VERSION_FILE)
IMG_DIR     = $(SRC_DIR)/img
IMGS        = $(wildcard $(IMG_DIR)/*.png) \
              $(wildcard $(IMG_DIR)/*.svg) \
              $(wildcard $(IMG_DIR)/*.edn)
CSV_DIR	    = $(SRC_DIR)/csv
CSVS	    = $(wildcard $(CSV_DIR)/*.csv)
GEN_DIR     = $(SRC_DIR)/generated
SCRIPTS_DIR = $(SRC_DIR)/scripts

# Output files
PDF_RESULT    := $(BUILD_DIR)/riscv-cheri.pdf
HTML_RESULT   := $(BUILD_DIR)/riscv-cheri.html

# Top asciidoc file of the document
HEADER_SOURCE := $(SRC_DIR)/riscv-cheri.adoc

# Generated files
GEN_SRC = $(GEN_DIR)/both_mode_insns_table_body.adoc               \
          $(GEN_DIR)/cap_mode_insns_table_body.adoc                \
          $(GEN_DIR)/csr_added_hybrid_table_body.adoc              \
          $(GEN_DIR)/csr_added_purecap_mode_d_table_body.adoc      \
          $(GEN_DIR)/csr_added_purecap_mode_m_table_body.adoc      \
          $(GEN_DIR)/csr_added_purecap_mode_s_table_body.adoc      \
          $(GEN_DIR)/csr_alias_action_table_body.adoc              \
          $(GEN_DIR)/csr_aliases_table_body.adoc                   \
          $(GEN_DIR)/csr_exevectors_table_body.adoc                \
          $(GEN_DIR)/csr_metadata_table_body.adoc                  \
          $(GEN_DIR)/csr_permission_table_body.adoc                \
          $(GEN_DIR)/csr_renamed_purecap_mode_d_table_body.adoc    \
          $(GEN_DIR)/csr_renamed_purecap_mode_m_table_body.adoc    \
          $(GEN_DIR)/csr_renamed_purecap_mode_s_table_body.adoc    \
          $(GEN_DIR)/csr_renamed_purecap_mode_u_table_body.adoc    \
          $(GEN_DIR)/illegal_insns_table_body.adoc                 \
          $(GEN_DIR)/legacy_mnemonic_insns_table_body.adoc         \
          $(GEN_DIR)/legacy_mode_insns_table_body.adoc             \
          $(GEN_DIR)/xlen_dependent_encoding_insns_table_body.adoc \
          $(GEN_DIR)/Zabhlrsc_insns_table_body.adoc                \
          $(GEN_DIR)/Zcheri_hybrid_insns_table_body.adoc           \
          $(GEN_DIR)/Zcheri_purecap_insns_table_body.adoc

# AsciiDoctor command
ASCIIDOC          = asciidoctor-pdf
EXTRA_ASCIIDOC_OPTIONS ?=

ASCIIDOC_OPTIONS  = --trace --verbose                                \
                    -a compress                                      \
                    -a mathematical-format=svg                       \
                    -a revnumber=$(VERSION)                          \
                    -a revremark=$(REVMARK)                          \
                    -a revdate=$(DATE)                               \
                    -a buildir=$(BUILD_DIR)                          \
                    -a srcdir=$(SRC_DIR)                             \
                    -a imagesdir=img                                 \
                    -a imagesoutdir=$(BUILD_DIR)/img                 \
                    -a cheri_v9_annotations=''                       \
                    -a pdf-fontsdir=docs-resources/fonts             \
                    -a pdf-theme=docs-resources/themes/riscv-pdf.yml \
                    --failure-level=ERROR $(EXTRA_ASCIIDOC_OPTIONS)
ASCIIDOC_REQUIRES = --require=asciidoctor-bibtex       \
                    --require=asciidoctor-diagram      \
                    --require=asciidoctor-mathematical

# File extension to backend map.
ASCIIDOC_BACKEND_.html = html5
ASCIIDOC_BACKEND_.pdf  = pdf

# Command to run Asciidoc to build a PDF or HTML document, depending on
# the output file ($@).
ASCIIDOC_BUILD_COMMAND = $(ASCIIDOC) \
                         $(ASCIIDOC_OPTIONS) \
                         $(ASCIIDOC_REQUIRES) \
                         $(HEADER_SOURCE) \
                         --backend=$(ASCIIDOC_BACKEND_$(suffix $@)) \
                         --out-file=$@

DOCKER_PATH  := $(shell command -v docker)
STDIN_IS_TTY := $(shell test -t 0 && echo yes)

ifdef DOCKER_PATH
    DOCKER_RUN_ARGS = --rm -v $(PWD):/build -w /build $(DOCKER_IMAGE) /bin/sh -c "$(ASCIIDOC_BUILD_COMMAND)"
    # `-it` is necessary so that ctrl-c works when running locally, however it
    # does not work in CI ("the input device is not a TTY") so we test for that too.
    ifdef STDIN_IS_TTY
        BUILD_COMMAND = docker run -it $(DOCKER_RUN_ARGS)
    else
        BUILD_COMMAND = docker run $(DOCKER_RUN_ARGS)
    endif
else
    BUILD_COMMAND = $(ASCIIDOC_BUILD_COMMAND)
endif

# Convenience targets
pdf: $(PDF_RESULT)
html: $(HTML_RESULT)
all: pdf html
generate: $(GEN_SRC)
download: $(CSVS)

$(BUILD_DIR):
	@echo "  DIR $@"
	@mkdir -p $@

%.pdf: $(SRCS) $(IMGS) $(GEN_SRC) | $(BUILD_DIR)
	@echo "  DOC $@"
	$(BUILD_COMMAND)

%.html: $(SRCS) $(IMGS) $(GEN_SRC) | $(BUILD_DIR)
	@echo "  DOC $@"
	$(BUILD_COMMAND)

# Rule to generate all the src/generated/*.adoc from the downloaded CSVs using a Python script.
$(GEN_SRC) &: $(CSVS) $(GEN_SCRIPT)
	@echo "  GEN $@"
	@$(GEN_SCRIPT) -o $(GEN_DIR) --csr $(CSV_DIR)/CHERI_CSR.csv --isa $(CSV_DIR)/CHERI_ISA.csv

# Rule to download CSVs. These files are checked in and only re-downloaded when you `make download`.
$(CSVS) &:
	@echo "  DOWN CSV (isa)"
	@curl -Lo src/csv/CHERI_ISA.csv "$(URL_ISA)"
	@echo >> src/csv/CHERI_ISA.csv
	@echo "  DOWN CSV (csr)"
	@curl -Lo src/csv/CHERI_CSR.csv "$(URL_CSR)"
	@echo >> src/csv/CHERI_CSR.csv

# Clean
clean:
	@echo "  CLEAN"
	@$(RM) -r $(PDF_RESULT) $(HTML_RESULT) $(GEN_SRC)

.PHONY: all generate download clean
