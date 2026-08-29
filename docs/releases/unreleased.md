# Ori Runtime — Unreleased

Changes merged to `main` after `v2.5.0-rc.6` are collected here until the next
candidate or release is cut.

## Fixed

- The installer no longer refuses a release whose venv `bin` carries a
  `__pycache__` directory. `v2.5.0-rc.6` cannot be installed on a Pi in either
  scope because its wheelhouse's `pyftdi` scripts are byte-compiled there at
  install time; the relocation now discards that cache and still refuses
  anything else at that name or any other directory in `bin`.

