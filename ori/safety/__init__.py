# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The release-owned safety registry (safety-profile/v1).

It is not yet the only Tier D path: packaged skill triggers still reach Tier D
until the cutover to the registry lands.

Tier D conditions come from the release-shipped profile set, activate from
commissioned zones, and owe nothing to installed skills. This package holds
that machinery; the profile grammar itself lives with the commissioning
modules that already consume it.
"""
