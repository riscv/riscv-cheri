# RISC-V Instruction Set Manual

[![RISC-V ISA Build](https://github.com/riscv/riscv-isa-manual/actions/workflows/isa-build.yml/badge.svg)](https://github.com/riscv/riscv-isa-manual/actions/workflows/isa-build.yml)

This repository contains the source files for the RISC-V Instruction Set Manual, which consists of the Unprivileged and Privileged volumes. The preface of each document indicates the version of each standard that has been formally ratified by RISC-V International.

This work is licensed under a [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/). See the [LICENSE](LICENSE) file for details.

The RISC-V Instruction Set Manual is organized into the following volumes:

- Volume I: Unprivileged Architecture
- Volume II: Privileged Architecture

## Official and Draft Versions

- **Compiled versions of the most recent drafts** of the specifications can be found on the [GitHub releases page](https://github.com/riscv/riscv-cheri/releases/latest).
- **HTML snapshots of the latest commit** can be viewed at the following locations:
  - [Standalone CHERI specification](https://riscv.github.io/riscv-cheri/)
  - [Standalone CHERI specification with additional non-frozen chapters](https://riscv.github.io/riscv-cheri/snapshot/riscv-cheri-full/)
  - [Unprivileged spec](https://riscv.github.io/riscv-cheri/snapshot/unprivileged/)
  - [Privileged spec](https://riscv.github.io/riscv-cheri/snapshot/privileged/)

## Contributing

If you would like to contribute to this documentation, please refer to the [Documentation Developer's Guide](https://github.com/riscv/docs-dev-guide).

The recommended method for building the PDF files is to use the Docker Image, as described in the [RISC-V Docs Base Container Image repository](https://github.com/riscv/riscv-docs-base-container-image).

Alternative build methods, such as local builds and GitHub Action builds, are also available and described in the Documentation Developer's Guide.

## Images not rendered for EPUB files

If the eBook reader does not support embedded images, uncomment `:data-uri:` lines in `src/riscv-privileged.adoc` and `src/riscv-unprivileged.adoc`.

### Known devices that cannot handle embedded images

- PocketBook InkPad 3

## Repo Activity

![Alt](https://repobeats.axiom.co/api/embed/ccec87dc4502f2ed7c216b670b5ed8efc33a1d4c.svg "Repobeats analytics image")
