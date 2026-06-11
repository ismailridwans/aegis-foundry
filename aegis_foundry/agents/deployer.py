"""Deployer agent: turns approved detections into native Splunk saved searches.

The Deployer is the only agent allowed to touch the Splunk management plane,
and only for rules the Governor explicitly approved. In live mode the
:class:`~aegis_foundry.core.interfaces.SplunkAdminClient` implementation
drives the Splunk management REST API (``services/saved/searches``) following
the splunk-sdk-python saved-search pattern: create-or-update with a cron
schedule, alert metadata, and the app namespace, returning a rollback token
so any deployment can be undone by the Verifier. In mock mode the same call
writes a local ``savedsearches.conf`` so judges can inspect the artifact
offline. The custom alert action shipped in ``splunk_app/`` files triage
notes when the detection fires, closing the loop from autonomous authoring
to analyst workflow.

Deployment semantics:

- ``APPROVE_ACTIVE``  -> mode "active": alerting saved search, alerts tracked.
- ``APPROVE_SHADOW``  -> mode "shadow": the saved search name gets a
  ``[SHADOW]`` suffix and ``alert.track = 0`` so it runs on schedule and
  logs results for verification, but never pages an analyst.

The scheduled search stays enabled in both modes — shadow rules must produce
real telemetry for the Verifier's forecast-vs-reality check.
"""

from __future__ import annotations

from aegis_foundry.agents.base import Agent
from aegis_foundry.core.interfaces import DeployError
from aegis_foundry.state import (
    Decision,
    DeploymentRecord,
    PipelineStage,
    PipelineState,
    RuleStatus,
)


class Deployer(Agent):
    """Deploy Governor-approved rules as scheduled Splunk saved searches."""

    name: str = "deployer"

    def run(self, state: PipelineState) -> PipelineState:
        """Create a saved search for every approved rule, then advance to VERIFY.

        Each deployment records a :class:`DeploymentRecord` carrying the
        rollback token returned by the admin client; a failed deploy is
        recorded as a non-fatal error and the remaining rules still deploy.
        """
        for rule_id, rule in list(state.rules.items()):
            if rule.status != RuleStatus.APPROVED:
                continue
            decision = state.decisions.get(rule_id)
            if decision is None:
                continue

            mode = "active" if decision.decision == Decision.APPROVE_ACTIVE else "shadow"
            saved_search_name = f"Aegis - {rule.name}"
            if mode == "shadow":
                saved_search_name += " [SHADOW]"
                # Shadow rules run on schedule but never page: results land in
                # the search artifact / summary only, not the triggered-alerts
                # queue (disabled-alerts semantics, schedule stays enabled).
                extra: dict[str, str] = {"alert.track": "0"}
            else:
                extra = {"alert.track": "1"}

            description = (
                f"{rule.description} | MITRE: {','.join(rule.mitre_techniques)} | "
                f"Deployed by Aegis Foundry run {state.run_id} v{rule.version}"
            )

            try:
                token = self.ctx.admin.create_saved_search(
                    saved_search_name,
                    rule.spl,
                    description=description,
                    cron_schedule=rule.cron_schedule,
                    disabled=False,
                    extra=extra,
                )
            except DeployError as exc:
                self.fail(
                    state,
                    f"deploy failed for rule {rule_id} "
                    f"('{saved_search_name}', mode={mode}): {exc}",
                )
                continue

            record = DeploymentRecord(
                rule_id=rule.rule_id,
                rule_version=rule.version,
                saved_search_name=saved_search_name,
                mode=mode,
                rollback_token=token,
            )
            state.deployments[rule.rule_id] = record
            rule.status = (
                RuleStatus.DEPLOYED_ACTIVE if mode == "active" else RuleStatus.DEPLOYED_SHADOW
            )

            self.emit(
                state,
                "rule_deployed",
                {
                    "rule_id": rule.rule_id,
                    "rule_version": rule.version,
                    "name": saved_search_name,
                    "mode": mode,
                    "rollback_token": token,
                },
            )

        state.stage = PipelineStage.VERIFY
        return state
