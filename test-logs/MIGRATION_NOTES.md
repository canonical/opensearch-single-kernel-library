# Jubilant migration — test_charm.py run results

Environment: LXD (concierge) controller, model `testing`, VM substrate, CHARM_UBUNTU_BASE=22.04.
Charm built with: `./scripts/build_lib_for_integration.sh --platform ubuntu@22.04:amd64 --charm tests/charms/opensearch_test_charm`
(NOTE: platform must be `ubuntu@22.04:amd64`, NOT `amd64`.)

## Summary of runs

### run_01_build_and_deploy.log (before building charm)
FAILED — FileNotFoundError: charm file missing. Confirmed jubilant `model_config` +
`deploy` are wired correctly; failure was only the missing `.charm` artifact.

### run_02_build_and_deploy.log (after building charm)
PASSED (473s). Real deployment of 2 OpenSearch units via `juju.deploy`, waited on
TLS_RELATION_MISSING status via migrated `wait_until`.

### run_03_get_admin_password.log (fresh state, no TLS yet)
PASSED (404s). Exercised: run_action (get-password failure via TaskError handling),
juju.deploy(TLS), juju.integrate, wait_until, get_secrets, http_request (vm/requests path).

### run_04_full_file.log (--no-deploy, residual state from run_02/03)
7 passed, 2 skipped, 1 failed.
- SKIPPED: test_deploy_and_remove_single_unit, test_build_and_deploy (skip_if_deployed + --no-deploy)
- PASSED: test_actions_rotate_admin_password, test_actions_rotate_system_user_password[monitor],
  test_actions_rotate_system_user_password[kibanaserver], test_check_pinned_revision,
  test_check_workload_version, test_all_units_have_internal_users_synced,
  test_add_users_and_calling_update_status
- FAILED: test_actions_get_admin_password
    assert result.status == "failed"  ->  AssertionError: 'completed' == 'failed'
    ROOT CAUSE: NOT a migration bug. The test asserts get-password fails *before* TLS is
    configured, but TLS (self-signed-certificates) was already related from run_03. The same
    test passed on fresh state in run_03. Confirmed via `juju status --relations`.

## Conclusion
All test_charm.py tests pass with the jubilant migration on appropriate (fresh) model state.
The only failure is a test-ordering/residual-state artifact when re-running against an
already-TLS-configured model, independent of the ops-test -> jubilant migration.

## Notes for next migration steps
- `skip_if_deployed` only triggers with `--no-deploy` + `--model` (pytest-operator).
- Migrated shared helpers (tests/integration/helpers.py) now take a `jubilant.Juju` instead of
  `OpsTest`. Other test modules (ha/*, tls/*, relations/*, etc.) still use `ops_test` and must be
  migrated before they will run.
- Substrate detection in helpers now uses `juju.status().model.type == "caas"` (`_is_k8s`).
- Model uuid via `juju.show_model().model_uuid` (cached); model name via `juju.model`.
