# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""``python -m ori.runtime``, the command the systemd unit runs."""

from ori.runtime._main import main

if __name__ == "__main__":
    main()
