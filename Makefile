# Makefile for RISC-V ISA Manuals
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
# the documentation for RISC-V ISA Manuals. It supports multiple build targets
# for generating documentation in various formats (PDF, HTML, EPUB).
#
# Building with a preinstalled docker container is recommended.
# Install by running:
#
#   docker pull riscvintl/riscv-docs-base-container-image:latest
#

DOCS := riscv-privileged riscv-unprivileged riscv-cheri

RELEASE_TYPE ?= draft
GIT_SHORT_HASH ?= -$(shell git rev-parse --short HEAD || true)
NEXT_VERSION = v0.9.7
ifeq ($(RELEASE_TYPE), draft)
CHERI_SPEC_VERSION ?= $(NEXT_VERSION)-draft$(GIT_SHORT_HASH)
else
CHERI_SPEC_VERSION ?= $(NEXT_VERSION)
endif

ifeq ($(RELEASE_TYPE), draft)
  WATERMARK_OPT := -a draft-watermark
  RELEASE_DESCRIPTION := DRAFT---NOT AN OFFICIAL RELEASE
else ifeq ($(RELEASE_TYPE), intermediate)
  WATERMARK_OPT :=
  RELEASE_DESCRIPTION := Intermediate Release
else ifeq ($(RELEASE_TYPE), official)
  WATERMARK_OPT :=
  RELEASE_DESCRIPTION := Official Release
else
  $(error Unknown build type; use RELEASE_TYPE={draft, intermediate, official})
endif

DATE ?= $(shell date +%Y%m%d)
DOCKER_BIN ?= docker
SKIP_DOCKER ?= $(shell if command -v ${DOCKER_BIN}  >/dev/null 2>&1 ; then echo false; else echo true; fi)
DOCKER_IMG := ghcr.io/riscv/riscv-docs-base-container-image:latest
ifneq ($(SKIP_DOCKER),true)
    DOCKER_IS_PODMAN = \
        $(shell ! ${DOCKER_BIN}  -v | grep podman >/dev/null ; echo $$?)
    ifeq "$(DOCKER_IS_PODMAN)" "1"
        # Modify the SELinux label for the host directory to indicate
        # that it can be shared with multiple containers. This is apparently
        # only required for Podman, though it is also supported by Docker.
        DOCKER_VOL_SUFFIX = :z
        DOCKER_EXTRA_VOL_SUFFIX = ,z
    else
        DOCKER_IS_ROOTLESS = \
            $(shell ! ${DOCKER_BIN} info -f '{{println .SecurityOptions}}' | grep rootless >/dev/null ; echo $$?)
        ifneq "$(DOCKER_IS_ROOTLESS)" "1"
            # Rooted Docker requires this flag so that the files it creates are
            # owned by the current user instead of root. Rootless docker does not
            # require it, and Podman doesn't either since it is always rootless.
            DOCKER_USER_ARG := --user $(shell id -u)
        endif
    endif

    DOCKER_CMD = \
        ${DOCKER_BIN} run --rm \
            -v ${PWD}/$@.workdir:/build${DOCKER_VOL_SUFFIX} \
            -v ${PWD}/src:/src:ro${DOCKER_EXTRA_VOL_SUFFIX} \
            -v ${PWD}/normative_rule_defs:/normative_rule_defs:ro${DOCKER_EXTRA_VOL_SUFFIX} \
            -v ${PWD}/docs-resources:/docs-resources:ro${DOCKER_EXTRA_VOL_SUFFIX} \
            -w /build \
            $(DOCKER_USER_ARG) \
            ${DOCKER_IMG} \
            /bin/sh -c
    DOCKER_QUOTE := "
else
    DOCKER_CMD = \
        cd $@.workdir &&
endif

# Default to incremental builds for the CHERI fork of the isa-manual, we have not seen this cause issues.
UNRELIABLE_BUT_FASTER_INCREMENTAL_BUILDS ?= 1
ifneq ($(UNRELIABLE_BUT_FASTER_INCREMENTAL_BUILDS),)
WORKDIR_SETUP = mkdir -p $@.workdir && ln -sfn ../../src ../../normative_rule_defs ../../docs-resources $@.workdir/
WORKDIR_TEARDOWN = mv $@.workdir/$@ $@
else
WORKDIR_SETUP = \
    rm -rf $@.workdir && \
    mkdir -p $@.workdir && \
    ln -sfn ../../src ../../normative_rule_defs ../../docs-resources $@.workdir/

WORKDIR_TEARDOWN = \
    mv $@.workdir/$@ $@ && \
    rm -rf $@.workdir
endif

SRC_DIR := src
BUILD_DIR := build
NORM_RULE_DEF_DIR := normative_rule_defs
DOC_NORM_TAG_SUFFIX := -norm-tags.json

DOCS_PDF := $(addprefix $(BUILD_DIR)/, $(addsuffix .pdf, $(DOCS)))
DOCS_HTML := $(addprefix $(BUILD_DIR)/, $(addsuffix .html, $(DOCS)))
DOCS_EPUB := $(addprefix $(BUILD_DIR)/, $(addsuffix .epub, $(DOCS)))
DOCS_NORM_TAGS := $(addprefix $(BUILD_DIR)/, $(addsuffix $(DOC_NORM_TAG_SUFFIX), $(DOCS)))
NORM_RULES := $(BUILD_DIR)/norm-rules.json

ENV := LANG=C.utf8
# Default to building only the CHERI changes
ifdef CHERI_MINIMAL
XTRA_ADOC_OPTS ?= -a minimal_cheri_changes_doc=1
else
XTRA_ADOC_OPTS ?=
endif
# Extra asciidoc flags passed on the command line
EXTRA_ASCIIDOC_OPTIONS ?=
ASCIIDOCTOR_PDF := $(ENV) asciidoctor-pdf
ASCIIDOCTOR_HTML := $(ENV) asciidoctor
ASCIIDOCTOR_EPUB := $(ENV) asciidoctor-epub3
ASCIIDOCTOR_TAGS := $(ENV) asciidoctor --backend tags --require=./docs-resources/converters/tags.rb
CREATE_NORM_RULE_TOOL := ruby docs-resources/tools/create_normative_rules.rb

OPTIONS := --trace --verbose \
           -a compress \
           -a mathematical-format=svg \
           -a pdf-fontsdir=docs-resources/fonts \
           -a pdf-theme=docs-resources/themes/riscv-pdf.yml \
           $(WATERMARK_OPT) \
           -a revnumber='$(CHERI_SPEC_VERSION)' \
           -a revdate='$(DATE)' \
           -a revremark='$(RELEASE_DESCRIPTION)' \
           -a docinfo=shared \
           $(XTRA_ADOC_OPTS) \
           $(EXTRA_ASCIIDOC_OPTIONS) \
           -D build \
           --failure-level=WARN
REQUIRES := --require=asciidoctor-bibtex \
            --require=asciidoctor-diagram \
            --require=asciidoctor-lists \
            --require=asciidoctor-mathematical \
            --require=asciidoctor-sail

# Downloaded Sail Asciidoc JSON, which includes all of
# the Sail code and can be embedded. We don't vendor it
# into this repo since it's quite large (~4MB).
SAIL_ASCIIDOC_JSON_URL_FILE = riscv_RV64.json.url
CHERI_GEN_DIR = $(SRC_DIR)/cheri/generated
SAIL_ASCIIDOC_JSON = $(CHERI_GEN_DIR)/riscv_RV64.json

.PHONY: all build clean build-docs build-pdf build-html build-epub build-tags build-norm-rules docker-pull-latest generate generate-cheri-tables

all: build

$(CHERI_GEN_DIR):
	mkdir -p "$@"
# Download the Sail JSON. The URL is stored in a file so if the URL changes
# Make will know to download it again.
$(SAIL_ASCIIDOC_JSON): $(SAIL_ASCIIDOC_JSON_URL_FILE) | $(CHERI_GEN_DIR)
	@curl --location '$(shell cat $<)' --output $@

generate: $(SAIL_ASCIIDOC_JSON)

# Rule to generate all the src/generated/*.adoc from the CSVs using a Python script.
CHERI_CSV_DIR = $(SRC_DIR)/cheri/csv
GEN_SCRIPT    = $(SRC_DIR)/cheri/scripts/generate_tables.py
# There is no need to declare all generated inputs as dependencies of the pdf
# targets since the outputs only change if either the CSV or python changes.
generate-cheri-tables: $(CHERI_CSV_DIR)/CHERI_CSR.csv $(CHERI_CSV_DIR)/CHERI_ISA.csv $(GEN_SCRIPT) | $(CHERI_GEN_DIR)
	@echo "  GEN $@"
	@$(GEN_SCRIPT) -o $(CHERI_GEN_DIR) --csr $(CHERI_CSV_DIR)/CHERI_CSR.csv --isa $(CHERI_CSV_DIR)/CHERI_ISA.csv

# Check if the docs-resources/global-config.adoc file exists. If not, the user forgot to check out submodules.
ifeq ("$(wildcard docs-resources/global-config.adoc)","")
  $(warning You must clone with --recurse-submodules to automatically populate the submodule 'docs-resources'.")
  $(warning Checking out submodules for you via 'git submodule update --init --recursive'...)
  $(shell git submodule update --init --recursive)
endif

build-pdf: $(DOCS_PDF)
build-html: $(DOCS_HTML)
build-epub: $(DOCS_EPUB)
build-tags: $(DOCS_NORM_TAGS)
build-norm-rules: $(NORM_RULES)
build: build-pdf build-html build-epub build-tags
# TODO: build-norm-rules

ALL_SRCS := $(shell git ls-files $(SRC_DIR)) $(SAIL_ASCIIDOC_JSON) generate-cheri-tables

# All normative rule definition input YAML files tracked under Git (ensure you at least stage new files).
NORM_RULE_DEF_FILES := $(shell git ls-files '$(NORM_RULE_DEF_DIR)/*.yaml')

# Add -t to each normative tag input filename and add prefix of "/" to make into absolute pathname.
NORM_TAG_FILE_ARGS := $(foreach relative_pname,$(DOCS_NORM_TAGS),-t /$(relative_pname))

# Add -d to each normative rule definition filename
NORM_RULE_DEF_ARGS := $(foreach relative_pname,$(NORM_RULE_DEF_FILES),-d $(relative_pname))

$(BUILD_DIR)/%.pdf: $(SRC_DIR)/%.adoc $(ALL_SRCS)
	$(WORKDIR_SETUP)
	$(DOCKER_CMD) $(DOCKER_QUOTE) $(ASCIIDOCTOR_PDF) $(OPTIONS) $(REQUIRES) $< $(DOCKER_QUOTE)
	$(WORKDIR_TEARDOWN)
	@echo -e '\n  Built \e]8;;file://$(abspath $@)\e\\$@\e]8;;\e\\\n'

$(BUILD_DIR)/%.html: $(SRC_DIR)/%.adoc $(ALL_SRCS)
	$(WORKDIR_SETUP)
	$(DOCKER_CMD) $(DOCKER_QUOTE) $(ASCIIDOCTOR_HTML) $(OPTIONS) $(REQUIRES) $< $(DOCKER_QUOTE)
	$(WORKDIR_TEARDOWN)
	@echo -e '\n  Built \e]8;;file://$(abspath $@)\e\\$@\e]8;;\e\\\n'

$(BUILD_DIR)/%.epub: $(SRC_DIR)/%.adoc $(ALL_SRCS)
	$(WORKDIR_SETUP)
	$(DOCKER_CMD) $(DOCKER_QUOTE) $(ASCIIDOCTOR_EPUB) $(OPTIONS) $(REQUIRES) $< $(DOCKER_QUOTE)
	$(WORKDIR_TEARDOWN)
	@echo -e '\n  Built \e]8;;file://$(abspath $@)\e\\$@\e]8;;\e\\\n'

$(BUILD_DIR)/%-norm-tags.json: $(SRC_DIR)/%.adoc $(ALL_SRCS) docs-resources/converters/tags.rb
	$(WORKDIR_SETUP)
	$(DOCKER_CMD) $(DOCKER_QUOTE) $(ASCIIDOCTOR_TAGS) $(OPTIONS) -a tags-match-prefix='norm:' -a tags-output-suffix='-norm-tags.json' $(REQUIRES) $< $(DOCKER_QUOTE)
	$(WORKDIR_TEARDOWN)

$(NORM_RULES): $(DOCS_NORM_TAGS) $(NORM_RULE_DEF_FILES)
	$(WORKDIR_SETUP)
	cp -f $(DOCS_NORM_TAGS) $@.workdir
	mkdir -p $@.workdir/build
	$(DOCKER_CMD) $(DOCKER_QUOTE) $(CREATE_NORM_RULE_TOOL) $(NORM_TAG_FILE_ARGS) $(NORM_RULE_DEF_ARGS) $@ $(DOCKER_QUOTE)
	$(WORKDIR_TEARDOWN)

# Update docker image to latest
docker-pull-latest:
	${DOCKER_BIN} pull ${DOCKER_IMG}

clean:
	@echo "Cleaning up generated files..."
	rm -rf $(BUILD_DIR)
	@echo "Cleanup completed."
