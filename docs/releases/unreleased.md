# Ori Runtime — Unreleased

Changes merged to `main` after `v2.5.0-rc.6` are collected here until the next
candidate or release is cut.

## Fixed

- The installer no longer refuses a release whose venv `bin` carries a
  `__pycache__` directory. `v2.5.0-rc.6` cannot be installed on a Pi in either
  scope because its wheelhouse's `pyftdi` scripts are byte-compiled there at
  install time; the relocation now discards that cache and still refuses
  anything else at that name or any other directory in `bin`.
- The shutdown checkpoint is now carried before the evidence routes are torn
  down. The stop path set the shutdown event first, which is what closes the
  outbound route, so the flush that followed found no session and the
  checkpoint waited for the next start; on the bench Pi the ledger showed it
  retained with no attempt. The checkpoint is issued and flushed before the
  event is set, the route drains once more on shutdown while the session is
  still granted, and drains are serialised so a nudge that overlaps the flush
  no longer carries the same artifact twice. Proven on the bench Pi against a
  LAN gateway: one attempt, acknowledged and retired before the route closed.

