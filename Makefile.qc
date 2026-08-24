# Build the ACE specification in the docs container, via the Qualcomm registry.
#
# SPDX-License-Identifier: CC-BY-SA-4.0

DOCS      := ace.adoc
VERSION   ?= v0.7.0
PDF_THEME := docs-resources/themes/riscv-pdf.yml
REQUIRES  := --require=asciidoctor-bibtex \
             --require=asciidoctor-diagram \
             --require=asciidoctor-lists \
             --require=asciidoctor-sail

DOCKER_IMG := docker-registry.qualcomm.com/proxy-cache-qcom/riscvintl/riscv-docs-base-container-image:latest

include Makefile.common
