"""Deterministic adapter contract tests; never invoke a native agent."""

import copy
import fcntl
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import projects_launcher as m


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "projects/dev"
        self.project.mkdir(parents=True)
        (self.project / "PROJECT.md").write_text("Existing durable role context")
        self.config = {
            "herdr_bin": "herdr",
            "projects_bin": "herdr-projects",
            "projects_root": str(self.project.parent),
            "socket": "/explicit/socket",
            "state_dir": str(self.root / "state"),
            "selector": ["ag-role"],
            "native_launchers": {
                "codex": "/managed/codex",
                "claude": "/managed/claude",
            },
            "bindings": {
                "dev/lead": {
                    "policy_role": "studio-lead",
                    "profiles": {"sol": "codex-sol", "claude": "claude-model"},
                }
            },
        }
        self.binding = self.config["bindings"]["dev/lead"]
        self.req = {"version": 1, "op": "ensure", "project": "dev", "role": "lead"}
        self.session = {
            "pane_id": "w1:p1",
            "terminal_id": "t1",
            "kind": "codex",
            "status": "idle",
            "project_dir": str(self.project),
        }

    def test_compatibility_fails_before_any_projects_mutation(self):
        with (
            patch.object(
                m, "output", side_effect=["herdr 0.9.0", "version: 0.9.0"]
            ) as out,
            self.assertRaises(m.Hold) as held,
        ):
            m.compatibility(self.config)
        self.assertEqual(held.exception.reason, "compatibility")
        self.assertEqual(out.call_count, 2)

    def test_live_reuse_skips_quota_then_waits_for_readiness(self):
        journal = {}
        with (
            patch.object(m, "current", return_value=self.session),
            patch.object(m, "select") as select,
        ):
            self.assertEqual(
                m.ensure(
                    self.config, self.binding, self.project, journal, lambda: None, 10
                )["state"],
                "starting",
            )
            self.assertEqual(
                m.ensure(
                    self.config, self.binding, self.project, journal, lambda: None, 13
                )["state"],
                "ready",
            )
            self.session["status"] = "working"
            self.assertEqual(
                m.ensure(
                    self.config, self.binding, self.project, journal, lambda: None, 14
                )["state"],
                "busy",
            )
        select.assert_not_called()

    def test_quota_failure_retains_without_start(self):
        with (
            patch.object(m, "current", return_value=None),
            patch.object(
                m,
                "select",
                return_value=(None, m.response("blocked", "quota", retry_at=123)),
            ),
            patch.object(m, "run") as run,
        ):
            result = m.ensure(
                self.config, self.binding, self.project, {}, lambda: None, 10
            )
        self.assertEqual(result["retry_at"], 123)
        run.assert_not_called()

    def test_cross_provider_new_start_uses_project_profile_no_native_session_id(self):
        journal = {
            "phase": "live",
            "session": {"kind": "claude", "session_id": "claude-only"},
        }
        with (
            patch.object(m, "current", side_effect=[None, self.session]),
            patch.object(m, "select", return_value=(("codex-sol", "sol", True), None)),
            patch.object(m, "run", return_value=SimpleNamespace(returncode=0)) as run,
        ):
            result = m.ensure(
                self.config, self.binding, self.project, journal, lambda: None, 10
            )
        args = run.call_args.args[1]
        self.assertEqual(
            args,
            [
                "herdr-projects",
                "--root",
                str(self.project.parent),
                "open",
                "dev",
                "--profile",
                "codex-sol",
                "--tab",
                "--socket",
                "/explicit/socket",
            ],
        )
        self.assertTrue(journal["fallback"])
        self.assertEqual(result["state"], "starting")
        self.assertNotIn("claude-only", args)

    def test_crash_during_activation_cannot_launch_again(self):
        with (
            patch.object(m, "current", return_value=None),
            patch.object(m, "select") as select,
            self.assertRaises(m.Hold) as held,
        ):
            m.ensure(
                self.config,
                self.binding,
                self.project,
                {"phase": "starting"},
                lambda: None,
                10,
            )
        self.assertEqual(held.exception.reason, "ambiguous_activation")
        select.assert_not_called()

    def test_busy_changed_terminal_and_duplicate_delivery(self):
        request = {
            **self.req,
            "op": "deliver",
            "request_id": "a" * 64,
            "content": "literal\n$(text)",
            "session": copy.deepcopy(self.session),
        }
        journal = {}
        with (
            patch.object(m, "current", return_value=self.session),
            patch.object(m, "run", return_value=SimpleNamespace(returncode=0)) as run,
        ):
            self.session["status"] = "working"
            self.assertEqual(
                m.deliver(
                    self.config,
                    self.binding,
                    self.project,
                    journal,
                    request,
                    lambda: None,
                )["state"],
                "busy",
            )
            self.session["status"] = "idle"
            self.session["terminal_id"] = "other"
            self.assertEqual(
                m.deliver(
                    self.config,
                    self.binding,
                    self.project,
                    journal,
                    request,
                    lambda: None,
                )["state"],
                "blocked",
            )
            self.session["terminal_id"] = "t1"
            self.assertEqual(
                m.deliver(
                    self.config,
                    self.binding,
                    self.project,
                    journal,
                    request,
                    lambda: None,
                )["state"],
                "delivered",
            )
            self.assertEqual(
                m.deliver(
                    self.config,
                    self.binding,
                    self.project,
                    journal,
                    request,
                    lambda: None,
                )["state"],
                "delivered",
            )
            self.assertEqual(run.call_count, 1)
            self.assertIn(request["content"], run.call_args.args[1])

    def test_prompt_timeout_is_uncertain_never_automatically_retried(self):
        req = {
            **self.req,
            "op": "deliver",
            "request_id": "a" * 64,
            "content": "task",
            "session": self.session,
        }
        journal = {}
        with (
            patch.object(m, "current", return_value=self.session),
            patch.object(m, "run", side_effect=m.Hold()) as run,
        ):
            for _ in range(2):
                self.assertEqual(
                    m.deliver(
                        self.config,
                        self.binding,
                        self.project,
                        journal,
                        req,
                        lambda: None,
                    )["state"],
                    "uncertain",
                )
        self.assertEqual(run.call_count, 1)

    def test_journal_lock_blocks_simultaneous_activation(self):
        state = Path(self.config["state_dir"])
        state.mkdir()
        name = hashlib.sha256(b"dev/lead").hexdigest()
        with (
            (state / (name + ".lock")).open("a") as lock,
            patch.object(m, "compatibility"),
            patch.object(m, "ensure") as ensure,
        ):
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                m.handle(self.config, self.req)
        ensure.assert_not_called()

    def test_project_binding_is_not_repo_path_and_duplicate_coordinators_rejected(self):
        other = self.project.parent / "paperclip"
        other.mkdir()
        (other / "PROJECT.md").write_text("separate context")
        self.config["bindings"]["paperclip/lead"] = self.binding.copy()
        self.assertNotEqual(
            m.binding_for(self.config, self.req)[2],
            m.binding_for(self.config, {**self.req, "project": "paperclip"})[2],
        )
        self.config["bindings"]["dev/second"] = self.binding.copy()
        with self.assertRaises(m.Hold):
            m.binding_for(self.config, self.req)

    def test_worker_uses_native_thread_lifecycle(self):
        instructions = self.root / "ROLE.md"
        instructions.write_text("Preserve these role instructions.")
        self.binding.update(
            mode="thread",
            instructions_file=str(instructions),
            repo="api",
            worker_startup_verified=True,
        )
        journal = {}
        with (
            patch.object(m, "current", side_effect=[None, self.session]),
            patch.object(m, "select", return_value=(("codex-sol", "sol", False), None)),
            patch.object(
                m,
                "run",
                return_value=SimpleNamespace(returncode=0, stdout='{"id":"t-0001"}'),
            ) as run,
        ):
            m.ensure(self.config, self.binding, self.project, journal, lambda: None, 10)
        self.assertEqual(journal["thread_id"], "t-0001")
        self.assertIn("thread", run.call_args.args[1])
        self.assertIn("--task-file", run.call_args.args[1])
        self.assertEqual(run.call_args.args[2], instructions.read_text())

    def test_worker_startup_requires_verified_upstream_detection(self):
        self.binding["mode"] = "thread"
        with (
            patch.object(m, "current", return_value=None),
            patch.object(m, "select") as select,
            self.assertRaises(m.Hold) as held,
        ):
            m.ensure(self.config, self.binding, self.project, {}, lambda: None, 10)
        self.assertEqual(held.exception.reason, "approval")
        select.assert_not_called()

    def test_idle_trust_dialog_is_not_prompt_ready(self):
        agent = {
            **self.session,
            "agent": "codex",
            "agent_status": "idle",
            "cwd": str(self.project),
        }
        with (
            patch.object(m, "snapshot", return_value={"agents": [agent]}),
            patch.object(
                m, "output", return_value="Hooks need review\nTrust all and continue"
            ),
            self.assertRaises(m.Hold) as held,
        ):
            m.current(self.config, self.binding, self.project, {})
        self.assertEqual(held.exception.reason, "approval")

    def test_opt_in_startup_delegates_to_project_policy_for_blocked_coordinator(self):
        self.binding["startup_policy"] = True
        agent = {**self.session, "agent": "claude", "agent_status": "blocked",
                 "cwd": str(self.project)}
        journal = {"ready_since": 1}
        with (patch.object(m, "snapshot", return_value={"agents": [agent]}),
              patch.object(m, "output", return_value='{"state":"accepted"}') as out,
              self.assertRaises(m.Hold) as held):
            m.current(self.config, self.binding, self.project, journal)
        self.assertEqual((held.exception.reason, held.exception.state), ("startup", "starting"))
        self.assertNotIn("ready_since", journal)
        self.assertEqual(out.call_args.args[1], m.hp(self.config, "native-startup", "dev", "--pane", "w1:p1"))

    def test_startup_disabled_held_unknown_or_manual_retains_request(self):
        self.binding["startup_policy"] = True
        agent = {**self.session, "agent": "codex", "agent_status": "idle",
                 "cwd": str(self.project)}
        for state in ["disabled", "held", "manual", "unrecognized"]:
            with (patch.object(m, "snapshot", return_value={"agents": [agent]}),
                  patch.object(m, "output", return_value=json.dumps({"state": state})),
                  self.assertRaises(m.Hold) as held):
                m.current(self.config, self.binding, self.project, {})
            self.assertEqual(held.exception.reason, "approval")

    def test_completed_startup_still_refuses_hooks_and_obeys_busy_state(self):
        self.binding["startup_policy"] = True
        agent = {**self.session, "agent": "codex", "agent_status": "idle",
                 "cwd": str(self.project)}
        with (patch.object(m, "snapshot", return_value={"agents": [agent]}),
              patch.object(m, "output", side_effect=['{"state":"complete"}', "Hooks need review"]),
              self.assertRaises(m.Hold) as held):
            m.current(self.config, self.binding, self.project, {})
        self.assertEqual(held.exception.reason, "approval")
        agent["agent_status"] = "working"
        with (patch.object(m, "snapshot", return_value={"agents": [agent]}),
              patch.object(m, "output", return_value='{"state":"complete"}')):
            session = m.current(self.config, self.binding, self.project, {})
        self.assertEqual(m.ready_result(session, {}, 10)["state"], "busy")

    def test_startup_completion_requires_new_ready_observations(self):
        self.binding["startup_policy"] = True
        agent = {**self.session, "agent": "codex", "agent_status": "idle",
                 "cwd": str(self.project)}
        with (patch.object(m, "snapshot", return_value={"agents": [agent]}),
              patch.object(m, "output", side_effect=['{"state":"complete"}', "Empty native composer"])):
            session = m.current(self.config, self.binding, self.project, {})
        journal = {}
        self.assertEqual(m.ready_result(session, journal, 10)["state"], "starting")
        self.assertEqual(m.ready_result(session, journal, 13)["state"], "ready")

    def test_select_validates_actual_profile_and_native_launcher(self):
        profile_dir = self.root / ".config/herdr-projects"
        profile_dir.mkdir(parents=True)
        profile_path = profile_dir / "config.toml"
        profile_path.write_text(
            '[profiles.codex-sol]\nagent="codex"\nmodel="gpt-sol"\neffort="high"\n'
        )
        report = {
            "plan": {
                "name": "sol",
                "kind": "codex",
                "command": ["/managed/codex"],
                "args": ["--model", "gpt-sol", "-c", 'model_reasoning_effort="high"'],
            },
            "decisions": [{}, {}],
        }
        with (
            patch.object(m.Path, "home", return_value=self.root),
            patch.object(
                m,
                "run",
                return_value=SimpleNamespace(returncode=0, stdout=json.dumps(report)),
            ),
        ):
            self.assertEqual(
                m.select(self.config, self.binding, self.project)[0],
                ("codex-sol", "sol", True),
            )
            profile_path.write_text(
                profile_path.read_text() + "[safety.default]\nyolo=true\n"
            )
            with self.assertRaises(m.Hold):
                m.select(self.config, self.binding, self.project)

    def test_failed_quota_reports_auth_unknown_and_reset_separately(self):
        for state, reason in [
            ("auth_error", "auth_error"),
            ("unknown", "unknown_capacity"),
            ("exhausted", "quota"),
        ]:
            report = {"decisions": [{"state": state, "retry_at": 123.5}]}
            with patch.object(
                m,
                "run",
                return_value=SimpleNamespace(returncode=75, stdout=json.dumps(report)),
            ):
                selected, held = m.select(self.config, self.binding, self.project)
            self.assertIsNone(selected)
            self.assertEqual(held["reason"], reason)
            self.assertEqual(held["retry_at"], 123)

    def test_explicit_recovery_updates_both_ledgers_contract(self):
        req = {
            **self.req,
            "op": "resolve",
            "request_id": "a" * 64,
            "disposition": "retry",
        }
        self.assertEqual(m.handle(self.config, req)["state"], "queued")
        req["disposition"] = "delivered"
        self.assertEqual(m.handle(self.config, req)["state"], "delivered")


if __name__ == "__main__":
    unittest.main()
