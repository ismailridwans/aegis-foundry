"""The pinned mock-SPL dialect against the committed fixture corpus."""

from __future__ import annotations

from aegis_foundry.core.mcp_client import MockMCPClient
from tests.conftest import FIXTURES_DIR, V1_SPL, V2_SPL


def _client() -> MockMCPClient:
    return MockMCPClient(FIXTURES_DIR)


def test_v1_matches_broad_powershell_noise():
    res = _client().run_search(V1_SPL, earliest="-90d", max_results=10000)
    assert res.ok
    assert 5600 <= res.count <= 6100


def test_v2_matches_only_encoded_non_service_accounts():
    res = _client().run_search(V2_SPL, earliest="-90d", max_results=10000)
    assert res.ok
    malicious = [e for e in res.results if e.get("label") == "malicious"]
    assert len(malicious) == 17
    assert 38 <= res.count <= 46
    assert all(e.get("user") != "svc_deploy" for e in res.results)
    assert all("-EncodedCommand" in e.get("CommandLine", "") for e in res.results)


def test_not_clause_excludes_users():
    with_not = _client().run_search(V2_SPL, earliest="-90d", max_results=10000)
    without_not = _client().run_search(
        V2_SPL.replace(' NOT user="svc_deploy"', ""), earliest="-90d", max_results=10000
    )
    assert without_not.count > with_not.count


def test_earliest_windowing_returns_final_week_only():
    res = _client().run_search(V2_SPL, earliest="-7d", max_results=10000)
    assert res.ok
    assert 2 <= res.count <= 4


def test_wildcards_match_case_insensitively():
    spl = V1_SPL.replace('"powershell.exe"', '"PowerShell.EXE"')
    res = _client().run_search(spl, earliest="-90d", max_results=10000)
    assert res.count >= 5600


def test_validate_spl_accepts_pinned_rules_and_rejects_garbage():
    c = _client()
    assert c.validate_spl(V1_SPL).valid
    assert c.validate_spl(V2_SPL).valid
    bad = c.validate_spl("index=botsv3 | foo |||")
    assert not bad.valid
    assert bad.error


def test_saved_search_inventory_loaded():
    rules = _client().list_saved_searches()
    assert len(rules) == 4
    covered = {t for r in rules for t in r.get("mitre_techniques", [])}
    assert "T1003.001" in covered
    assert "T1059.001" not in covered
