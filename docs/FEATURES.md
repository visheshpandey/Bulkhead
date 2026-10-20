# Features

Bulkhead evaluates descriptive AI-agent actions against user intent. It accepts
file reads/writes, commands, web requests, and GitHub actions, and returns an
`allow`, `block`, or `quarantine` decision with findings and a risk score.

- Deterministic detection normalizes encoded text, Unicode disguises, paths,
  and common leetspeak before checking injection, sensitive data, exfiltration,
  destructive commands, and intent constraints.
- The synthetic Decoy captures suspicious descriptions and generates a learned
  Rule that blocks a repeat fingerprint.
- SQLite stores events, Attacks, Rules, and capture receipts; the API exposes
  state, live SSE, exports, and Markdown reports.
- The local dashboard provides Activity, Test scenarios, Arena, Lab, Rules,
  Exports, and agent integration snippets.
- Python client/guard helpers, a coding-agent hook, and `bulkhead-mcp` provide
  agent-facing entry points.

Bulkhead does not execute the proposed tool call. See [security](SECURITY.md).

## Offline verification map

Each row pairs a feature with its implementation symbol and a descriptive
pytest function. `tests/test_features_manifest.py` checks both references using
source ASTs, without importing modules as part of manifest discovery.

| Feature | Implementation | Verification |
| --- | --- | --- |
| `policy_evaluation` | `app.core.policy:PolicyGateway.evaluate` | `test_policy_evaluation_returns_allow_block_and_decoy` |
| `supported_actions` | `app.core.models:ActionType` | `test_supported_actions_accept_all_five_action_types` |
| `risk_findings` | `app.core.detectors:ThreatDetector.inspect` | `test_risk_findings_explain_decoy_decision` |
| `action_validation` | `app.core.models:AgentAction` | `test_action_validation_rejects_unsafe_and_unknown_input` |
| `detector_normalization` | `app.core.detectors:normalize_detection_text` | `test_detector_normalization_catches_encoded_injection` |
| `intent_boundaries` | `app.core.policy:PolicyGateway._intent_findings` | `test_intent_boundaries_block_outside_targets_and_network` |
| `immunity_rules` | `app.audit.ledger:EventLedger.generate_immunity_rule` | `test_immunity_rules_block_replayed_attacks` |
| `honeyworld_decoy` | `app.honeyworld.simulation:HoneyWorld.execute` | `test_honeyworld_decoy_never_calls_external_tools` |
| `audit_ledger` | `app.audit.ledger:EventLedger` | `test_audit_ledger_persists_and_reloads_records` |
| `api_evaluation` | `app.api.routes:evaluate` | `test_api_evaluation_accepts_flat_and_object_actions` |
| `api_state` | `app.api.routes:state` | `test_api_state_includes_events_rules_and_captures` |
| `api_exports` | `app.api.routes:export_audit` | `test_api_exports_and_reports_use_stable_labels` |
| `markdown_report` | `app.api.routes:incident_report` | `test_markdown_report_describes_the_attack_and_decoy` |
| `live_event_stream` | `app.api.routes:live_event_stream` | `test_live_event_stream_announces_audit_and_reset` |
| `agent_guard` | `app.agents.client:bulkhead_guard` | `test_agent_guard_prevents_tool_invocation` |
| `hook` | `examples.hooks.pretooluse:main` | `test_hook_command_sends_json_and_returns_nonzero_for_decoyed_action` |
| `mcp_adapter` | `app.agents.mcp_server:BulkheadMCPServer.handle` | `test_mcp_adapter_evaluates_without_invoking_tools` |
| `lab_parser` | `app.agents.lab_parser:parse_instruction_actions` | `test_lab_parser_turns_page_instructions_into_actions` |
| `public_sessions` | `app.core.public_demo:SessionStore.get_or_create` | `test_public_sessions_isolate_state` |
| `lab_scoreboard` | `app.api.routes:run_lab` | `test_lab_scoreboard_counts_attacks_but_not_harmless_pages` |
| `rule_lifecycle` | `app.api.routes:patch_rule` | `test_rule_lifecycle_and_audit_views` |
| `scenarios` | `app.main:dashboard` | `test_scenarios_are_pure_json_with_fifteen_distinct_actions` |
| `scenario_expectations` | `app.core.policy:PolicyGateway.evaluate` | `test_scenario_expectations_against_real_gateway` |
| `dashboard_sections` | `app.main:dashboard` | `test_dashboard_sections_serve_activity_test_arena_lab_rules_exports_and_integrations` |
| `health_endpoint` | `app.main:health` | `test_health_endpoint_returns_liveness` |
| `concurrent_evaluation` | `app.core.policy:PolicyGateway.evaluate` | `test_concurrent_evaluation_handles_200_requests_under_three_seconds` |
| `action_evaluation` | `app.core.policy:PolicyGateway.evaluate` | `test_action_evaluation_returns_structured_decision` |
| `intent_checks` | `app.core.policy:PolicyGateway._intent_findings` | `test_intent_checks_reject_network_by_default` |
| `zero_trust_default` | `app.core.policy:PolicyGateway._intent_findings` | `test_zero_trust_default_allows_only_workspace_reads` |
| `path_normalisation` | `app.core.detectors:normalize_posix_target` | `test_path_normalisation_rejects_escape` |
| `prompt_injection_plain` | `app.core.detectors:ThreatDetector.inspect` | `test_prompt_injection_plain_is_detected` |
| `prompt_injection_base64` | `app.core.detectors:ThreatDetector.inspect` | `test_prompt_injection_base64_is_detected` |
| `prompt_injection_hex` | `app.core.detectors:ThreatDetector.inspect` | `test_prompt_injection_hex_is_detected` |
| `prompt_injection_zero_width` | `app.core.detectors:ThreatDetector.inspect` | `test_prompt_injection_zero_width_is_detected` |
| `prompt_injection_leetspeak` | `app.core.detectors:ThreatDetector.inspect` | `test_prompt_injection_leetspeak_is_detected` |
| `secret_detection` | `app.core.detectors:ThreatDetector.inspect` | `test_secret_detection_finds_fake_material` |
| `shell_exfiltration` | `app.core.detectors:ThreatDetector.inspect` | `test_shell_exfiltration_is_detected` |
| `payload_key_detection` | `app.core.detectors:ThreatDetector.inspect` | `test_payload_key_detection_finds_nested_keys` |
| `destructive_commands` | `app.core.detectors:ThreatDetector.inspect` | `test_destructive_commands_are_blocked` |
| `decoy_honeyworld` | `app.honeyworld.simulation:HoneyWorld.execute` | `test_decoy_honeyworld_returns_fake_receipt` |
| `immunity_create` | `app.audit.ledger:EventLedger.generate_immunity_rule` | `test_immunity_create_learns_first_attack` |
| `immunity_enable` | `app.api.routes:patch_rule` | `test_immunity_enable_restores_rule_blocking` |
| `immunity_disable` | `app.api.routes:patch_rule` | `test_immunity_disable_allows_replay_evaluation` |
| `immunity_delete` | `app.api.routes:delete_rule` | `test_immunity_delete_removes_rule` |
| `audit_ledger_persistence` | `app.audit.ledger:EventLedger` | `test_audit_ledger_persistence_round_trips_events` |
| `exports` | `app.api.routes:export_audit` | `test_exports_include_json_and_csv_records` |
| `attack_reports` | `app.api.routes:incident_report` | `test_attack_reports_render_markdown` |
| `live_stream` | `app.api.routes:live_event_stream` | `test_live_stream_emits_reset_boundary` |
| `sessions_rate_limits` | `app.core.public_demo:RequestRateLimiter.allow` | `test_sessions_rate_limits_enforce_budgets` |
| `mcp_server` | `app.agents.mcp_server:BulkheadMCPServer.handle` | `test_mcp_server_returns_policy_result` |
| `python_guard` | `app.agents.client:bulkhead_guard` | `test_python_guard_blocks_before_tool_call` |
| `demo_flow` | `app.api.routes:run_demo` | `test_demo_flow_preserves_allow_decoy_block_sequence` |
| `attack_lab` | `app.api.routes:run_lab` | `test_attack_lab_scores_contained_attacks` |
| `accessibility` | `app.main:dashboard` | `test_accessibility_contract_has_landmarks_labels_and_live_regions` |
| `responsive_layout` | `app.main:dashboard` | `test_responsive_layout_contract_has_breakpoints_and_scroll_wrapper` |
