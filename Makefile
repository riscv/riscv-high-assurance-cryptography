# Build the ACE specification in the RISC-V docs container.
#
# SPDX-License-Identifier: CC-BY-SA-4.0

DOCS      := ace.adoc
VERSION   ?= v0.6.0
PDF_THEME := docs-resources/themes/riscv-pdf.yml
REQUIRES  := --require=asciidoctor-bibtex \
             --require=asciidoctor-diagram \
             --require=asciidoctor-mathematical \
             --require=asciidoctor-kroki \
             --require=asciidoctor-lists \
             --require=asciidoctor-sail \
             --require=./src/preprocessor.rb

DOCKER_IMG := ghcr.io/riscv/riscv-docs-base-container-image:latest
#DOCKER_IMG := ghcr.io/riscv/riscv-docs-base-container-image@sha256:c90f312cef31366106486940fbcafe63baee437df79171d321e8135672d819ae
#DOCKER_IMG := ghcr.io/riscv/riscv-docs-base-container-image:21a2c824d312dcfe4119b368266ff8ca79b29b61

include Makefile.common
