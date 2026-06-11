Aegis Foundry - Splunk app (v0.1.0)
===================================

What this app provides
----------------------
* aegis_audit index definition (indexes.conf) - destination for the agent
  "flight recorder" audit trail and AI triage notes.
* Sourcetypes aegis:flight_recorder (JSON lines, indexed extractions) and
  aegis:triage_note (props.conf).
* Two dashboards: "ATT&CK Coverage Forge" (technique coverage posture,
  detections forged this week, forecast-vs-observed alert volume) and
  "Agent Flight Recorder" (full audit event stream, per-agent timeline,
  pending human approvals).
* Two operational saved searches: an hourly flight-recorder ingest check
  (disabled by default) and an on-demand coverage snapshot.
* Custom alert action "aegis_triage" (bin/aegis_triage_alert.py): attach it
  to any detection and it writes an AI-assisted (or deterministic-heuristic)
  triage note back into aegis_audit as sourcetype aegis:triage_note.

Where the agents live
---------------------
The Python agent runtime (the nine governed agents, orchestrator, mock and
live Splunk clients) lives at the repository root, NOT inside this app.
This app is the Splunk-side landing zone: the Deployment agent creates
approved detections as saved searches in this app's namespace at runtime via
the management REST API (servicesNS/nobody/aegis_foundry/saved/searches), so
they appear under local/savedsearches.conf with full rollback support.

Getting audit events into aegis_audit
-------------------------------------
The runtime appends one JSON object per agent action to
runs/<run_id>/flight_recorder.jsonl. Ship them with either:

1. HTTP Event Collector - create a HEC token with default index aegis_audit
   and sourcetype aegis:flight_recorder and point the runtime at it; or
2. File monitor - on the machine running the agents, add an inputs.conf
   monitor stanza for the runs directory, e.g.:

     [monitor://<repo>/runs/*/flight_recorder.jsonl]
     index = aegis_audit
     sourcetype = aegis:flight_recorder

Triage notes from the aegis_triage alert action arrive via the REST
receivers/simple endpoint automatically (no extra input needed).

Support
-------
Splunk Enterprise / Splunk Cloud 9.x. No binary dependencies; the alert
action uses the Splunk-bundled Python 3 interpreter and the standard library
only. Package with scripts/package_app.py -> dist/aegis_foundry.spl.
