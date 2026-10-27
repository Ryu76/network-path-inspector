"""제품 entrypoint FILE ONLY 역할의 허용범위 회귀. CLI/모델/네트워크를 호출하지 않는다."""
import ast
import hashlib
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
APP_PATHS = (
    'apps/network-quick-check/Cargo.toml',
    'apps/network-quick-check/src/lib.rs',
    'apps/network-quick-check/src/main.rs',
    'apps/network-quick-check/tests/resolver_dispatch.rs',
)


def assignments(filename, name):
    tree = ast.parse((ROOT / 'tools' / filename).read_text(encoding='utf-8'))
    return [ast.literal_eval(node.value) for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]


class QuickAppScopeTests(unittest.TestCase):
    def setUp(self):
        self.writer = assignments('ai_pro_harness.py', 'allowed')[0]
        self.audit = assignments('audit_ai_pro_runs.py', 'RULES')[0]

    def test_writer_and_auditor_roles_match(self):
        self.assertEqual(self.writer, self.audit)

    def test_exact_four_app_outputs(self):
        self.assertEqual(self.writer['qgquickapp'], APP_PATHS)

    def test_no_directory_wildcard(self):
        self.assertFalse(any(path.endswith('/') for path in self.writer['qgquickapp']))

    def test_parent_manifest_and_lock_excluded(self):
        for path in ['Cargo.toml', 'Cargo.lock', 'AGENTS.md', 'PRD.md']:
            self.assertNotIn(path, self.writer['qgquickapp'])

    def test_shared_engines_and_readme_excluded(self):
        for path in ['crates/network-core/src/runner.rs', 'crates/network-resolver/src/lib.rs',
                     'apps/network-quick-check/README.md', 'apps/network-quick-check/build.rs']:
            self.assertNotIn(path, self.writer['qgquickapp'])

    def test_tcp_replay_role_exact_single_test_only(self):
        self.assertEqual(self.writer['qgtcpreplay'], ('crates/network-core/tests/tcp_product_projection_replay.rs',))

    def test_tcp_replay_actor_cannot_modify_protected_engine(self):
        self.assertNotIn('crates/npi-probes/src/engine.rs', self.writer['qgtcpreplay'])
        self.assertFalse(any(path.endswith('/') for path in self.writer['qgtcpreplay']))

    def test_tcp_replay_cannot_modify_manifest_contract_or_production(self):
        for path in ['Cargo.toml', 'Cargo.lock', 'crates/network-core/src/quick.rs',
                     'contracts/quick-check-interface-v0.1.json']:
            self.assertNotIn(path, self.writer['qgtcpreplay'])

    def test_native_tcp_product_role_exact_single_new_test(self):
        self.assertEqual(self.writer['qgtcpnative'],
                         ('crates/network-core/tests/tcp_product_native_equivalence.rs',))

    def test_native_tcp_role_has_no_production_or_existing_replay_access(self):
        for path in ['crates/npi-probes/src/engine.rs', 'crates/network-core/src/runner.rs',
                     'crates/network-core/tests/tcp_product_projection_replay.rs',
                     'Cargo.toml', 'Cargo.lock', 'contracts/quick-check-interface-v0.1.json']:
            self.assertNotIn(path, self.writer['qgtcpnative'])

    def test_native_tcp_role_never_uses_directory_wildcard(self):
        self.assertFalse(any(path.endswith('/') for path in self.writer['qgtcpnative']))

    def test_explicit_tcp_role_exact_three_app_files(self):
        self.assertEqual(self.writer['qgdevtcp'], ('apps/network-quick-check/src/lib.rs',
            'apps/network-quick-check/src/diagnostic_cli.rs',
            'apps/network-quick-check/tests/explicit_tcp_entry.rs'))

    def test_explicit_tcp_metadata_worker_and_core_excluded(self):
        for path in ['Cargo.toml', 'Cargo.lock', 'apps/network-quick-check/Cargo.toml',
                     'apps/network-quick-check/src/main.rs',
                     'apps/network-quick-check/tests/resolver_dispatch.rs',
                     'crates/network-core/src/runner.rs', 'crates/npi-probes/src/engine.rs']:
            self.assertNotIn(path, self.writer['qgdevtcp'])

    def test_explicit_tcp_never_uses_directory_wildcard(self):
        self.assertFalse(any(path.endswith('/') for path in self.writer['qgdevtcp']))

    def test_gui_state_role_exact_three_files(self):
        self.assertEqual(self.writer['qgguistate'], (
            'apps/network-quick-check/src/lib.rs',
            'apps/network-quick-check/src/gui_state.rs',
            'apps/network-quick-check/src/gui_state_tests.rs'))

    def test_gui_state_role_does_not_change_entry_core_or_dependencies(self):
        for path in ['Cargo.toml', 'Cargo.lock', 'apps/network-quick-check/Cargo.toml',
                     'apps/network-quick-check/src/main.rs',
                     'apps/network-quick-check/src/diagnostic_cli.rs',
                     'apps/network-quick-check/tests/public_entry_rejection.rs',
                     'crates/network-core/src/targets.rs',
                     'crates/network-core/src/runner.rs',
                     'crates/npi-probes/src/engine.rs', 'PRD.md']:
            self.assertNotIn(path, self.writer['qgguistate'])

    def test_gui_state_role_has_no_directory_wildcard(self):
        self.assertFalse(any(path.endswith('/') for path in self.writer['qgguistate']))

    def test_gui_inputs_role_exact_six_source_files(self):
        self.assertEqual(self.writer['qgguiinputs'], (
            'apps/network-quick-check/src/lib.rs',
            'apps/network-quick-check/src/gui_entry.rs',
            'apps/network-quick-check/src/gui_presenter.rs',
            'apps/network-quick-check/src/gui_presenter_tests.rs',
            'apps/network-quick-check/src/native_gui.rs',
            'apps/network-quick-check/src/native_gui_tests.rs'))

    def test_gui_inputs_cannot_rewrite_state_core_entry_or_dependencies(self):
        for path in ['Cargo.toml', 'Cargo.lock', 'apps/network-quick-check/Cargo.toml',
                     'apps/network-quick-check/src/main.rs',
                     'apps/network-quick-check/src/diagnostic_cli.rs',
                     'apps/network-quick-check/src/gui_state.rs',
                     'apps/network-quick-check/src/gui_state_tests.rs',
                     'apps/network-quick-check/tests/public_entry_rejection.rs',
                     'crates/network-core/src/targets.rs', 'crates/npi-probes/src/engine.rs']:
            self.assertNotIn(path, self.writer['qgguiinputs'])

    def test_gui_inputs_scope_has_no_directory_wildcard(self):
        self.assertFalse(any(path.endswith('/') for path in self.writer['qgguiinputs']))

    def test_corrective_coordinator_role_same_exact_scope(self):
        self.assertEqual(self.writer['qgcoordfix'], self.writer['qgcoordinator'])

    def test_coordinator_role_exact_two_new_files(self):
        self.assertEqual(self.writer['qgcoordinator'], (
            'apps/network-quick-check/src/gui_coordinator.rs',
            'apps/network-quick-check/src/gui_coordinator_tests.rs'))

    def test_result_export_role_exact_two_new_files(self):
        self.assertEqual(self.writer['qgresults'], (
            'apps/network-quick-check/src/result_view.rs',
            'apps/network-quick-check/src/result_export.rs'))

    def test_new_independent_roles_cannot_wire_gui_or_modify_dependencies(self):
        for role in ['qgcoordinator', 'qgresults']:
            self.assertFalse(any(path.endswith('/') for path in self.writer[role]))
            for path in ['Cargo.toml', 'Cargo.lock', 'apps/network-quick-check/Cargo.toml',
                         'apps/network-quick-check/src/lib.rs',
                         'apps/network-quick-check/src/gui_presenter.rs',
                         'apps/network-quick-check/src/gui_state.rs',
                         'apps/network-quick-check/src/native_gui.rs',
                         'crates/network-core/src/runner.rs', 'PRD.md']:
                self.assertNotIn(path, self.writer[role])
        self.assertFalse(set(self.writer['qgcoordinator']) & set(self.writer['qgresults']))

    def test_typed_session_bridge_role_exact_three_paths(self):
        self.assertEqual(self.writer['qgbridge'], (
            'apps/network-quick-check/src/gui_presenter.rs',
            'apps/network-quick-check/src/gui_run_session.rs',
            'apps/network-quick-check/src/gui_run_session_tests.rs'))

    def test_typed_session_bridge_cannot_wire_native_or_rewrite_shared_models(self):
        self.assertFalse(any(path.endswith('/') for path in self.writer['qgbridge']))
        for path in ['Cargo.toml', 'Cargo.lock', 'apps/network-quick-check/Cargo.toml',
                     'apps/network-quick-check/src/lib.rs',
                     'apps/network-quick-check/src/gui_state.rs',
                     'apps/network-quick-check/src/gui_coordinator.rs',
                     'apps/network-quick-check/src/gui_coordinator_tests.rs',
                     'apps/network-quick-check/src/gui_result_render.rs',
                     'apps/network-quick-check/src/native_gui.rs',
                     'apps/network-quick-check/src/gui_entry.rs',
                     'apps/network-quick-check/src/gui_presenter_tests.rs',
                     'crates/network-core/src/runner.rs', 'PRD.md']:
            self.assertNotIn(path, self.writer['qgbridge'])

    def test_native_runtime_role_reuses_exact_two_host_paths(self):
        self.assertEqual(self.writer['qgruntime'], self.writer['qgcoordinator'])

    def test_pure_render_role_exact_one_new_source(self):
        self.assertEqual(self.writer['qgrender'], ('apps/network-quick-check/src/gui_result_render.rs',))

    def test_runtime_and_renderer_cannot_wire_gui_or_modify_contracts(self):
        self.assertFalse(set(self.writer['qgruntime']) & set(self.writer['qgrender']))
        for role in ['qgruntime', 'qgrender']:
            self.assertFalse(any(path.endswith('/') for path in self.writer[role]))
            for path in ['Cargo.toml', 'Cargo.lock', 'apps/network-quick-check/Cargo.toml',
                         'apps/network-quick-check/src/lib.rs',
                         'apps/network-quick-check/src/gui_state.rs',
                         'apps/network-quick-check/src/gui_presenter.rs',
                         'apps/network-quick-check/src/native_gui.rs',
                         'apps/network-quick-check/src/result_view.rs',
                         'apps/network-quick-check/src/result_export.rs',
                         'crates/network-core/src/runner.rs', 'PRD.md']:
                self.assertNotIn(path, self.writer[role])

    def test_run_entry_and_native_ui_roles_have_disjoint_exact_scope(self):
        self.assertEqual(self.writer['qgrunentry'], (
            'apps/network-quick-check/src/gui_run_entry.rs',
            'apps/network-quick-check/src/gui_run_entry_tests.rs'))
        self.assertEqual(self.writer['qgrunui'], (
            'apps/network-quick-check/src/native_gui.rs',
            'apps/network-quick-check/src/native_gui_tests.rs'))
        self.assertFalse(set(self.writer['qgrunentry']) & set(self.writer['qgrunui']))
        for role in ['qgrunentry', 'qgrunui']:
            self.assertFalse(any(p.endswith('/') for p in self.writer[role]))
            for p in ['Cargo.toml', 'Cargo.lock', 'PRD.md',
                      'apps/network-quick-check/src/lib.rs',
                      'apps/network-quick-check/src/gui_entry.rs',
                      'apps/network-quick-check/src/gui_run_session.rs',
                      'apps/network-quick-check/src/gui_coordinator.rs',
                      'crates/network-core/src/runner.rs']:
                self.assertNotIn(p, self.writer[role])

    def test_prior_runner_scope_unchanged(self):
        self.assertEqual(self.writer['qg2runner'],
                         ('crates/network-core/src/runner.rs', 'crates/network-core/tests/runner.rs'))

    def test_existing_cli_38_case_corpus_was_not_rewritten(self):
        source = (ROOT / 'tools/verify_quick_app_entry_owned_native.py').read_text(encoding='utf-8')
        corpus = source[source.index("    flag='--npi-dns-worker-v1'"):
                        source.index('    # EXPLICIT_ENTRY_PARENT_REJECTION_CASES')]
        self.assertEqual(hashlib.sha256(corpus.encode()).hexdigest(),
                         '9f2cd57b0de269243e147481077f4e7f729ed7afe78ba8e08afebe64da44ff1f')

    def test_existing_cli_baseline_stays_separate_from_explicit_profile(self):
        original = assignments('verify_quick_app_entry_owned_native.py', 'FINAL')[0]
        self.assertEqual(tuple(original), APP_PATHS)
        self.assertEqual(original['apps/network-quick-check/src/lib.rs'],
                         '683097037fe29c59af84d69dbddc50bdd27f7a16bd272cb86553b3c3038353f7')

    def test_role_is_separate_from_docs_and_shared_core(self):
        self.assertIn('qgplan2', self.writer)
        self.assertIn('qgcore', self.writer)
        self.assertNotEqual(self.writer['qgquickapp'], self.writer['qgplan2'])
        self.assertNotEqual(self.writer['qgquickapp'], self.writer['qgcore'])


if __name__ == '__main__':
    unittest.main()
