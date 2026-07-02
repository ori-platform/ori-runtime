# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from ori.utils.bool_utils import is_truthy


def test_is_truthy_accepts_common_enabled_strings():
    assert is_truthy("true") is True
    assert is_truthy("1") is True
    assert is_truthy("yes") is True
    assert is_truthy("on") is True


def test_is_truthy_rejects_common_disabled_strings():
    assert is_truthy("false") is False
    assert is_truthy("0") is False
    assert is_truthy("off") is False
    assert is_truthy("no") is False
