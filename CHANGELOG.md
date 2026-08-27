
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-08-27

### Changed

- Renamed the PyPI distribution to `kb-fastapi-rbac`.
- Added production deployment and integration guidance.
- Added Docker-based PostgreSQL test workflow using `.env`.

### Fixed

- Fixed SQLAlchemy transaction handling for DML statements with `RETURNING`.
- Fixed role hierarchy traversal, cycle detection, wildcard permissions, scoped checks, audit metadata, and assignment history behavior.
