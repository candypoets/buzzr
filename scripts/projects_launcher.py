#!/usr/bin/env python3
"""buzzr launcher v1 adapter for Herdr Projects 0.2.25 and model-lanes.

Project/thread lifecycle stays in herdr-projects. This adapter owns only a small
activation/delivery journal and checks the explicitly configured role binding.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import tomllib


class Hold(Exception):
    def __init__(self, reason="configuration", state="blocked"):
        self.reason, self.state = reason, state


def response(state, reason="", **fields):
    return {"version": 1, "state": state, "reason": reason, **fields}


def read_json(path, default=None):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return {} if default is None else default


def save(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def clean_env(config):
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("BUZZ", "NOSTR", "PAPERCLIP", "HERDR_"))
        and k != "CLIPROXYAPI_MANAGEMENT_KEY"
    }
    env["HERDR_SOCKET_PATH"] = config["socket"]
    env["HERDR_BIN_PATH"] = config["herdr_bin"]
    return env


def run(config, args, text=None, timeout=40):
    try:
        return subprocess.run(
            args,
            input=text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=clean_env(config),
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Hold("unavailable") from None


def output(config, args):
    proc = run(config, args)
    if proc.returncode:
        raise Hold("unavailable")
    return proc.stdout


def version(text):
    match = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", text)
    if not match:
        raise Hold("compatibility")
    return tuple(map(int, match.groups()))


def compatibility(config):
    client = version(output(config, [config["herdr_bin"], "--version"]))
    server = version(output(config, [config["herdr_bin"], "status", "server"]))
    if min(client, server) < (0, 9, 1):
        raise Hold("compatibility")
    projects = version(output(config, [config["projects_bin"], "--version"]))
    if not (0, 2, 25) <= projects < (0, 3, 0):
        raise Hold("compatibility")


def hp(config, *args):
    return [config["projects_bin"], "--root", config["projects_root"], *args]


def snapshot(config):
    document = json.loads(output(config, [config["herdr_bin"], "api", "snapshot"]))
    return document["result"]["snapshot"]


def binding_for(config, request):
    if request.get("version") != 1 or request.get("op") not in (
        "ensure",
        "deliver",
        "resolve",
    ):
        raise Hold()
    key = request["project"] + "/" + request["role"]
    binding = config["bindings"][key]
    coordinators = [
        k
        for k, b in config["bindings"].items()
        if k.split("/")[0] == request["project"]
        and b.get("mode", "coordinator") == "coordinator"
    ]
    if len(coordinators) > 1:
        raise Hold()
    root = Path(config["projects_root"]).expanduser().resolve()
    project = (root / request["project"]).resolve()
    if project.parent != root or not (project / "PROJECT.md").is_file():
        raise Hold()
    if binding.get("mode", "coordinator") not in ("coordinator", "thread"):
        raise Hold()
    record = read_json(project / ".state/project.json")
    if record.get("status") == "archived":
        raise Hold()
    return key, binding, project


def current(config, binding, project, journal):
    snap = snapshot(config)
    agents = snap.get("agents", [])
    if binding.get("mode", "coordinator") == "thread":
        thread_id = journal.get("thread_id")
        if not thread_id:
            return None
        record_path = project / "threads" / (thread_id + ".toml")
        if not record_path.is_file():
            raise Hold("ambiguous_activation")
        record = tomllib.loads(record_path.read_text())
        if record.get("status") != "open":
            # A completed worker is not resurrected. The next mention gets a
            # new native project thread, preserving the previous report/history.
            return None
        matches = [
            a
            for a in agents
            if a.get("pane_id") == record.get("pane_id")
            and a.get("cwd") == record.get("cwd")
        ]
        if record.get("prompt_pending"):
            raise Hold("startup", "starting")
    else:
        record = read_json(project / ".state/coordinator.json")
        if record.get("socket") and record["socket"] != config["socket"]:
            raise Hold()
        cwd = str(project)
        matches = [a for a in agents if cwd in (a.get("cwd"), a.get("foreground_cwd"))]
    if len(matches) > 1:
        raise Hold("ambiguous_activation")
    if not matches:
        return None
    agent = matches[0]
    if not agent.get("terminal_id"):
        raise Hold("startup", "starting")
    if binding.get("startup_policy", False):
        # Herdr Projects owns native chooser recognition, persistent claims,
        # project membership checks and the user-owned opt-in policy.
        result = json.loads(output(config, hp(config, "native-startup", project.name,
                                              "--pane", agent["pane_id"])))
        state = result.get("state")
        if state != "complete":
            journal.pop("ready_since", None)
            if state in ("waiting", "accepted"):
                raise Hold("startup", "starting")
            raise Hold("approval")
    if agent.get("agent_status") in ("idle", "done"):

        # Some native versions misclassify startup trust/hook choosers as idle.
        # Refuse known dialogs without printing screen contents or answering them.
        screen = output(
            config,
            [
                config["herdr_bin"],
                "agent",
                "read",
                agent["pane_id"],
                "--format",
                "text",
                "--source",
                "visible",
            ],
        ).lower()
        if any(
            marker in screen
            for marker in (
                "trust this folder",
                "do you trust",
                "hooks need review",
                "new mcp server found in this project",
                "new mcp servers found in this project",
                "managed settings require approval",
                "trust all and continue",
                "yes, i trust",
                "trust and continue",
            )
        ):
            raise Hold("approval")
    return {
        "pane_id": agent["pane_id"],
        "terminal_id": agent["terminal_id"],
        "kind": agent["agent"],
        "status": agent.get("agent_status", "unknown"),
        "project_dir": str(project),
    }


def ready_result(session, journal, now):
    if session["status"] not in ("idle", "done"):
        journal.pop("ready_since", None)
        return response(
            "busy" if session["status"] == "working" else "blocked",
            "busy" if session["status"] == "working" else "approval",
        )
    identity = session["terminal_id"]
    if journal.get("ready_terminal") != identity:
        journal["ready_terminal"] = identity
        journal["ready_since"] = now
    journal.setdefault("ready_since", now)
    # Re-observe readiness across polls. Never type directly into a first frame.
    if now - journal["ready_since"] < 2:
        return response("starting", "startup")
    return response(
        "ready",
        session=session,
        route=journal.get("route"),
        fallback=journal.get("fallback", False),
    )


def select(config, binding, project):
    selector = config["selector"]
    proc = run(
        config,
        [
            selector[0],
            binding["policy_role"],
            *selector[1:],
            "--plan",
            "--cwd",
            str(project),
        ],
    )
    if proc.returncode == 75:
        report = json.loads(proc.stdout)
        reasons = [d["state"] for d in report.get("decisions", [])]
        resets = [
            int(d["retry_at"]) for d in report.get("decisions", []) if d.get("retry_at")
        ]
        return None, response(
            "blocked",
            "quota"
            if reasons and all(s in ("exhausted", "headroom") for s in reasons)
            else "auth_error"
            if "auth_error" in reasons
            else "unknown_capacity",
            retry_at=min(resets) if resets else None,
        )
    if proc.returncode:
        raise Hold("unknown_capacity")
    report = json.loads(proc.stdout)
    plan = report["plan"]
    profile = binding["profiles"][plan["name"]]
    # Herdr Projects launches concrete native kinds, not custom executables.
    # An operator must attest each managed executable is equivalent to the
    # native command used by Herdr (same proxy, account pool and permissions).
    if plan["command"] != [config["native_launchers"][plan["kind"]]]:
        raise Hold()
    config_path = Path.home() / ".config/herdr-projects/config.toml"
    profiles = tomllib.loads(config_path.read_text())
    entry = profiles["profiles"][profile]
    args = []
    if entry.get("model"):
        args += ["--model", entry["model"]]
    if entry.get("effort"):
        args += (
            ["--effort", entry["effort"]]
            if entry["agent"] == "claude"
            else ["-c", "model_reasoning_effort=" + json.dumps(entry["effort"])]
        )
    args += entry.get("args", [])
    if entry["agent"] != plan["kind"] or args != plan["args"]:
        raise Hold()
    safety = profiles.get("safety", {})
    effective = {**safety.get("default", {}), **safety.get(str(project), {})}
    if (
        effective.get("yolo")
        or effective.get("coordinator_agent_args")
        or effective.get("thread_agent_args")
    ):
        raise Hold()
    return (profile, plan["name"], len(report.get("decisions", [])) > 1), None


def ensure(config, binding, project, journal, persist, now):
    session = current(config, binding, project, journal)
    if session:
        journal["phase"] = "live"
        journal["session"] = session
        return ready_result(session, journal, now)
    if journal.get("phase") == "starting":
        # Includes crash after Herdr accepted start but before its record became
        # readable. Do not blindly create a second coordinator/thread.
        raise Hold("ambiguous_activation")
    if binding.get("mode", "coordinator") == "thread" and not binding.get(
        "worker_startup_verified", False
    ):
        # Upstream #63 can submit a pending brief on an undetected trust screen.
        # Enable only after validating/fixing native startup detection locally.
        raise Hold("approval")
    selected, held = select(config, binding, project)
    if held:
        return held
    profile, route, fallback = selected
    journal.update(phase="starting", route=route, fallback=fallback)
    journal.pop("ready_terminal", None)
    persist()
    if binding.get("mode", "coordinator") == "coordinator":
        # open records the pane before start, reuses live sessions, and resumes
        # only when native kind AND profile match. Never pass --new or session IDs.
        proc = run(
            config,
            hp(
                config,
                "open",
                project.name,
                "--profile",
                profile,
                "--tab",
                "--socket",
                config["socket"],
            ),
        )
    else:
        # Workers are native project threads; their reports/worktrees remain
        # under Herdr Projects. No second task list or worker scheduler.
        task = Path(binding["instructions_file"]).read_text()
        args = hp(
            config,
            "thread",
            "start",
            project.name,
            "--profile",
            profile,
            "--title",
            "Buzz role " + binding["policy_role"],
            "--task-file",
            "-",
        )
        if binding.get("repo"):
            args += ["--repo", binding["repo"]]
        proc = run(config, args, task)
        if proc.returncode == 0:
            journal["thread_id"] = json.loads(proc.stdout)["id"]
            persist()
    if proc.returncode:
        # An unsuccessful open can still have created a pane. Reconciliation
        # will discover it; if none appears, retain the ambiguous activation.
        raise Hold("ambiguous_activation")
    session = current(config, binding, project, journal)
    if session:
        journal["phase"] = "live"
        return ready_result(session, journal, now)
    return response("starting", "startup", route=route, fallback=fallback)


def deliver(config, binding, project, journal, request, persist):
    message_id = request["request_id"]
    if not re.fullmatch("[a-f0-9]{64}", message_id):
        raise Hold()
    previous = journal.setdefault("deliveries", {}).get(message_id)
    if previous:
        return response(
            "delivered" if previous == "delivered" else "uncertain",
            "ambiguous_delivery" if previous != "delivered" else "",
        )
    session = current(config, binding, project, journal)
    expected = request.get("session", {})
    if not session or any(
        session.get(k) != expected.get(k)
        for k in ("pane_id", "terminal_id", "kind", "project_dir")
    ):
        return response("blocked", "startup")
    if session["status"] not in ("idle", "done"):
        return response("busy", "busy")
    journal["deliveries"][message_id] = "sending"
    persist()
    try:
        proc = run(
            config,
            [
                config["herdr_bin"],
                "agent",
                "prompt",
                session["pane_id"],
                request["content"],
                "--wait",
                "--until",
                "working",
                "--until",
                "blocked",
                "--timeout",
                "10000",
            ],
            timeout=15,
        )
    except Hold:
        return response("uncertain", "ambiguous_delivery")
    if proc.returncode:
        return response("uncertain", "ambiguous_delivery")
    journal["deliveries"][message_id] = "delivered"
    journal.pop("ready_since", None)
    persist()
    return response(
        "delivered", route=journal.get("route"), fallback=journal.get("fallback", False)
    )


def handle(config, request, now=None):
    now = time.time() if now is None else now
    key, binding, project = binding_for(config, request)
    if request["op"] != "resolve":
        compatibility(config)
    directory = Path(config["state_dir"]).expanduser()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = hashlib.sha256(key.encode()).hexdigest()
    # Serializes simultaneous bridge calls, and remains held through the start.
    with (directory / (name + ".lock")).open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = directory / (name + ".json")
        journal = read_json(path)
        persist = lambda: save(path, journal)
        try:
            if request["op"] == "resolve":
                message_id = request["request_id"]
                if not re.fullmatch("[a-f0-9]{64}", message_id) or request.get(
                    "disposition"
                ) not in ("retry", "delivered"):
                    raise Hold()
                if request["disposition"] == "retry":
                    journal.setdefault("deliveries", {}).pop(message_id, None)
                    if journal.get("phase") == "starting":
                        journal.pop("phase")
                    return response("queued")
                journal.setdefault("deliveries", {})[message_id] = "delivered"
                return response("delivered")
            return (
                ensure(config, binding, project, journal, persist, now)
                if request["op"] == "ensure"
                else deliver(config, binding, project, journal, request, persist)
            )
        finally:
            persist()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text())
        request = json.loads(sys.stdin.read(1024 * 1024))
        answer = handle(config, request)
    except Hold as held:
        answer = response(held.state, held.reason)
    except BlockingIOError:
        answer = response("starting", "startup")
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        answer = response("blocked", "configuration")
    print(json.dumps(answer))


if __name__ == "__main__":
    main()
