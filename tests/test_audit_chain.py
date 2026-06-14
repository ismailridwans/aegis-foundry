"""Tamper-evident audit ledger: hash chaining and tamper detection."""

from __future__ import annotations

from aegis_foundry.state import PipelineState


def _state_with_events(n: int = 5) -> PipelineState:
    state = PipelineState()
    for i in range(n):
        state.add_audit("agent", f"action_{i}", {"i": i})
    return state


def test_chain_is_intact_after_emission():
    state = _state_with_events()
    ok, broken = state.verify_audit_chain()
    assert ok is True
    assert broken is None
    # each event links to the prior event's hash
    assert state.audit[0].prev_hash == "0" * 64
    for prev, cur in zip(state.audit, state.audit[1:]):
        assert cur.prev_hash == prev.event_hash


def test_chain_survives_round_trip():
    state = _state_with_events()
    clone = PipelineState.from_dict(state.to_dict())
    ok, broken = clone.verify_audit_chain()
    assert ok is True and broken is None


def test_tampering_a_past_event_breaks_the_chain():
    state = _state_with_events(6)
    # An attacker edits the detail of event #3 but cannot recompute every hash.
    state.audit[2].detail = {"i": 999, "exfiltrated": True}
    ok, broken = state.verify_audit_chain()
    assert ok is False
    assert broken == state.audit[2].seq


def test_tampering_a_stored_hash_breaks_the_chain():
    state = _state_with_events(4)
    state.audit[1].event_hash = "deadbeef" * 8
    ok, broken = state.verify_audit_chain()
    assert ok is False
    # the forged hash is caught either at the edited event or the next link
    assert broken in (state.audit[1].seq, state.audit[2].seq)
