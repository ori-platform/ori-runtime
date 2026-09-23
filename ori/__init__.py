# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from ori.hardware.lgpio_workdir import contain as _contain_lgpio

# Before anything imports a GPIO library: every Ori process owns the directory
# lgpio writes into, so none leaves a pipe in whatever directory it ran from.
_contain_lgpio()
