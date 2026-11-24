# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""docs/MQTT_SECURITY.md lists every gateway-api/v2 topic the runtime routes:
the topic table and broker ACL example by direction, and the retain=false list
with every topic the contract does not retain (gateway-api/v2, Topics)."""

from __future__ import annotations

import re
from pathlib import Path

from ori.gateway import payload_bounds as pb

DOC = Path(__file__).resolve().parents[1] / "docs" / "MQTT_SECURITY.md"
RUNTIME_USER = "ori-runtime-dev-01"
GATEWAY_USER = "ori-gateway-site-a"

TO_GATEWAY = "runtime_to_gateway"
TO_RUNTIME = "gateway_to_runtime"

# gateway-api/v2 Topics direction for every topic family in PAYLOAD_MAXIMA.
DIRECTIONS = {
    pb.GATEWAY_HEALTH: TO_RUNTIME,
    pb.RUNTIME_HEARTBEAT: TO_GATEWAY,
    pb.RUNTIME_POSTURE: TO_GATEWAY,
    pb.ALERT_DELIVERY: TO_GATEWAY,
    pb.ALERT_DELIVERY_ACK: TO_RUNTIME,
    pb.REASONING_REQUEST: TO_GATEWAY,
    pb.REASONING_RESPONSE: TO_RUNTIME,
    pb.ENRICHMENT_REQUEST: TO_GATEWAY,
    pb.ENRICHMENT_RESPONSE: TO_RUNTIME,
    pb.EXPORT_REQUEST: TO_RUNTIME,
    pb.EXPORT_RESPONSE: TO_GATEWAY,
    pb.EVIDENCE_OUTBOUND: TO_GATEWAY,
    pb.EVIDENCE_OUTBOUND_ACK: TO_RUNTIME,
    pb.EVIDENCE_INBOUND: TO_RUNTIME,
    pb.EVIDENCE_INBOUND_ACK: TO_GATEWAY,
    pb.LAN_PROPOSAL: TO_GATEWAY,
    pb.LAN_REPLY: TO_RUNTIME,
    pb.LAN_DISCLOSURE_REQUEST: TO_RUNTIME,
    pb.LAN_DISCLOSURE_RESPONSE: TO_GATEWAY,
}


# gateway-api/v2 publishes the posture record retained; every other topic is not.
RETAINED = {pb.RUNTIME_POSTURE}


def _example_topic(template: str) -> str:
    return template.replace("{device_id}", "dev-01").replace("{request_id}", "+")


def _acl_grants() -> dict[str, set[tuple[str, str]]]:
    """Each user's (grant, topic) lines from the ACL example's conf block."""
    blocks = re.findall(r"```conf\n(.*?)```", DOC.read_text(), re.DOTALL)
    acl = [b for b in blocks if f"user {RUNTIME_USER}" in b]
    assert len(acl) == 1, "expected exactly one ACL example block"
    grants: dict[str, set[tuple[str, str]]] = {}
    user = None
    for line in acl[0].splitlines():
        words = line.split()
        if words[:1] == ["user"]:
            user = words[1]
            grants[user] = set()
        elif words[:1] == ["topic"]:
            assert user is not None and len(words) == 3, line
            grants[user].add((words[1], words[2]))
    return grants


def _expected(sender_is_runtime: bool) -> set[tuple[str, str]]:
    return {
        (
            "write" if (direction == TO_GATEWAY) == sender_is_runtime else "read",
            _example_topic(topic),
        )
        for topic, direction in DIRECTIONS.items()
    }


def test_every_routed_topic_has_a_direction() -> None:
    assert set(DIRECTIONS) == set(pb.PAYLOAD_MAXIMA), (
        "state each topic's gateway-api/v2 direction here. This map is copied "
        "from the contract, not read from it: a direction changed in both this "
        "map and the doc is not checked against the contract."
    )


def test_runtime_user_is_granted_each_topic_by_direction() -> None:
    assert _acl_grants()[RUNTIME_USER] == _expected(sender_is_runtime=True)


def test_gateway_user_is_granted_each_topic_by_direction() -> None:
    assert _acl_grants()[GATEWAY_USER] == _expected(sender_is_runtime=False)


def _section(heading: str) -> str:
    text = DOC.read_text()
    start = text.index(f"\n## {heading}\n")
    end = text.find("\n## ", start + 1)
    return text[start : end if end != -1 else None]


def test_topic_contract_table_names_each_topic_publisher() -> None:
    rows = re.findall(
        r"^\| [^|]+ \| (\w+) \| [^|]+ \| `([^`]+)` \|$",
        _section("Topic Contract"),
        re.MULTILINE,
    )
    expected = {
        (
            "runtime" if direction == TO_GATEWAY else "gateway",
            _example_topic(topic),
        )
        for topic, direction in DIRECTIONS.items()
    }
    assert set(rows) == expected
    assert len(rows) == len(expected)


def test_retain_false_list_holds_every_unretained_topic() -> None:
    listed = re.findall(r"^- `(ori/[^`]+)`$", _section("Retained Messages"), re.M)
    assert set(listed) == set(pb.PAYLOAD_MAXIMA) - RETAINED
    assert len(listed) == len(set(listed))
