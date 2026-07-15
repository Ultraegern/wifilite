# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/2.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Changes:

- `WifiNetwork::bssids()` now returns `&[String]` instead of an `impl Iterator<Item = &str>`. Use `WifiNetwork::bssids_iter()` for the iterator behavior.

## [0.1.0] - 2026-02-27

Initial release.
