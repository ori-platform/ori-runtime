# Ori Runtime — Unreleased

Changes merged to `main` after `v2.5.0-rc.7` are collected here until the next
candidate or release is cut.

## Added

- The runtime verifies, retains and reports a commissioned safety binding
  (`ori-specs/commissioned-safety-binding/v1`). The binding envelope at
  `commissioning/binding.json` beside `ori.yaml` is verified through the
  contract's twelve ordered stages against commissioning anchors the
  installer delivers in the service environment, retained whole in the state
  store, and reported in health under `commissioning` with the verdict by
  stage and reason. Declared actuating hardware with no accepted binding
  refuses a hardened start and degrades a development one. The safety profile
  set ships with the release and is loaded under its closed grammar.
  `actions.relay.active_high` is refused from `ori.yaml`: polarity is a
  commissioned fact. Nothing actuates through the mapping yet; that seam is
  the next change.

