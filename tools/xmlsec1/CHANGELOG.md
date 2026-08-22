# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.11](https://github.com/structured-world/xml-sec/releases/tag/v0.1.11) - 2026-08-22

### Added

- *(cli)* add native xmlsec1 command

### Fixed

- *(cli)* decrypt first embedded payload
- *(cli)* bound lax key selection
- *(cli)* bound key candidate work
- *(xmldsig)* preserve digest dependencies
- *(cli)* preserve verification dependencies
- *(cli)* close dependency review gaps
- *(cli)* close resource tracking gaps
- *(cli)* harden bounded manifest handling
- *(cli)* harden compatibility edge cases
- *(xmlenc)* type candidate budget exhaustion
- *(cli)* resolve compatibility review
- *(cli)* harden input and key handling
- *(xml)* enforce UTF-16 byte order
- *(xml)* normalize transcoded declarations
- *(cli)* clarify option applicability
- *(cli)* validate signing key identity
- *(cli)* bound key candidate processing
- *(cli)* bound lax key selection
- *(xmlenc)* bound recipient key search
- *(cli)* bound certificate sources
- *(cli)* fail strict verification key errors
- *(xmlenc)* process decrypt candidates lazily
- *(cli)* bound certificate and RSA inputs
- *(cli)* validate configured trust inputs
- *(xmlenc)* bound authenticated key retries
- *(cli)* bound key candidate processing
- *(cli)* validate compound key inputs
- *(cli)* harden verification key search
- *(cli)* enforce mutation boundaries
- *(cli)* preserve positional sentinels
- *(cli)* tighten capability ledger checks
- *(cli)* enforce donor input contracts
- *(cli)* harden compatibility contracts

### Refactored

- *(cli)* clarify diagnostic routing
