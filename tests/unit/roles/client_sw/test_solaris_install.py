"""Regression tests of actual Solaris task ordering with safe action stubs.

Run with unittest or pytest. No Solaris commands, privilege changes, SSH or
package installation occur. Set SOLARIS_TEST_ANSIBLE_PLAYBOOK to exercise another
already-installed controller, including Ansible 2.9/2.10.
"""

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[4]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SOLARIS = ROOT / "roles/client_sw/tasks/os/solaris"
PLAYBOOK = os.environ.get("SOLARIS_TEST_ANSIBLE_PLAYBOOK", "ansible-playbook")
TARGET_VERSION = "7.1.0.1000"
NEWER_CATALOG_VERSION = "9.0.0.1000"
LINKED_CHILD = "zone:sample child /zones/sample/root\n"


def walk_tasks(tasks):
    for task in tasks:
        yield task
        for section in ("block", "rescue", "always"):
            for nested in walk_tasks(task.get(section, [])):
                yield nested


@unittest.skipUnless(shutil.which(PLAYBOOK), "ansible-playbook is required")
class SolarisInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="solaris-role-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o755)

    def run_case(self, route="equal", registered="svr4", fault="", check=False,
                 linked=LINKED_CHILD, major="11",
                 state="present", publisher_exists=True, publisher_enabled=True,
                 enabled_label="Publisher enabled", detail_rc=0, svr4_rc=0,
                 packages=("vasclnt",), newer_catalog_version=""):
        sandbox = Path(tempfile.mkdtemp(dir=str(self.root)))
        sandbox.chmod(0o755)
        for name in ("stage-root", "controller", "actions", "bin", "local-tmp"):
            (sandbox / name).mkdir(mode=0o755)
        private = sandbox / "private"
        private.mkdir(mode=0o700)
        old_directory = private / "ansible-as-client_sw"
        old_directory.mkdir(mode=0o700)
        old_archive = old_directory / "sas.p5p"
        old_archive.write_bytes(b"pre-existing caller media\n")
        old_archive.chmod(0o600)
        source = sandbox / "controller/sas.p5p"
        source.write_bytes(b"test archive content\n")
        source.chmod(0o600)
        if fault == "media":
            source.unlink()
        unrelated = sandbox / "stage-root/unrelated"
        unrelated.mkdir()
        (unrelated / "keep").write_text("not owned by the install operation\n")

        for action in ("command", "shell", "copy", "file", "tempfile"):
            shutil.copyfile(
                str(FIXTURES / "solaris_actions.py"),
                str(sandbox / "actions" / (action + ".py")),
            )
        # Defence in depth: even a broken action-plugin override cannot invoke
        # an actual package command from the local machine's PATH.
        for command in ("pkg", "pkginfo", "pkgrm", "pkgadd"):
            guard = sandbox / "bin" / command
            guard.write_text("#!/bin/sh\nexit 99\n")
            guard.chmod(0o755)
        config = sandbox / "ansible.cfg"
        config.write_text(
            "[defaults]\nretry_files_enabled = False\nstdout_callback = default\n"
        )
        versions = {
            "equal": TARGET_VERSION, "downgrade": "8.0.0.1000",
            "upgrade": "6.0.0.1000", "install": "",
        }
        data = {
            "fault": fault,
            "installed": {
                package: {
                    "system": registered if route != "install" else "",
                    "version": versions[route],
                } for package in packages
            },
            "target_version": TARGET_VERSION,
            "newer_catalog_version": newer_catalog_version,
            "linked": linked, "publisher_exists": publisher_exists,
            "publisher_enabled": publisher_enabled,
            "enabled_label": enabled_label, "detail_rc": detail_rc,
            "svr4_rc": svr4_rc,
            "origins": [
                ["true", "https://packages.example.invalid/primary/", "-"],
                ["false", "https://packages.example.invalid/secondary/",
                 "http://proxy.example.invalid:8080"],
            ],
            "publisher_queries": 0, "temp_origin": None,
            "events": [], "commands": [], "stages": [], "cleaned": [],
            "worker_checks": [],
        }
        initial_installed = {
            package: dict(installed) for package, installed in data["installed"].items()
        }
        state_path = sandbox / "state.json"
        state_path.write_text(json.dumps(data))
        variables = {
            "solaris_test_root": str(sandbox),
            "solaris_test_major": major,
            "solaris_test_python": sys.executable,
            "solaris_test_packages": [
                {"key": package, "value": state} for package in packages
            ],
            "client_sw_pkgs": {
                "packages": {
                    package: {
                        "path": str(source), "file": "sas.p5p",
                        "vers": TARGET_VERSION,
                    } for package in packages
                },
            },
        }
        environment = dict(os.environ)
        environment.update({
            "ANSIBLE_CONFIG": str(config),
            "ANSIBLE_ACTION_PLUGINS": str(sandbox / "actions"),
            "ANSIBLE_ROLES_PATH": str(ROOT / "roles"),
            "ANSIBLE_LOCAL_TEMP": str(sandbox / "local-tmp"),
            "ANSIBLE_LOG_PATH": os.devnull,
            "ANSIBLE_NOCOLOR": "1",
            # This existing collection uses string truthiness in routing;
            # modern 2.19+ controllers otherwise reject its old conditionals.
            "ANSIBLE_ALLOW_BROKEN_CONDITIONALS": "True",
            "PATH": str(sandbox / "bin") + os.pathsep + os.environ["PATH"],
        })
        command = [
            PLAYBOOK, "-i", "localhost,", "-c", "local",
            str(FIXTURES / "solaris.yml"), "-e", json.dumps(variables),
        ]
        if check:
            command.append("--check")
        completed = subprocess.run(
            command, cwd=str(ROOT), env=environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90,
        )
        data = json.loads(state_path.read_text())
        data["initial_installed"] = initial_installed
        data["sandbox"] = sandbox
        data["old_archive"] = old_archive
        data["source"] = source
        self.assertTrue(data["commands"], completed.stdout)
        self.assertTrue((unrelated / "keep").is_file(), completed.stdout)
        return completed, data

    @staticmethod
    def removals(data):
        return [
            event for event in data["commands"]
            if "pkgrm" in event["argv"]
            or event["argv"][:2] == ["pkg", "uninstall"]
        ]

    @staticmethod
    def ips_installs(data):
        return [
            event for event in data["commands"]
            if event["argv"][:2] == ["pkg", "install"]
        ]

    @staticmethod
    def publisher_mutations(data):
        return [
            event for event in data["commands"]
            if event["argv"][:2] in (
                ["pkg", "set-publisher"], ["pkg", "unset-publisher"],
            )
        ]

    def assert_success(self, completed):
        self.assertEqual(completed.returncode, 0, completed.stdout)

    def assert_rejected(self, completed, data, reason):
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertIn(reason, completed.stdout)
        self.assertEqual(self.removals(data), [], completed.stdout)
        self.assertEqual(self.publisher_mutations(data), [], completed.stdout)
        self.assertEqual(data["stages"], data["cleaned"], completed.stdout)

    def test_preflight_rejections_preserve_installed_packages_on_all_routes(self):
        faults = {
            "ssl": "SSL client credentials",
            "system": "SYSPUB=true",
            "linked": "stub linked discovery error",
            "publisher": "stub publisher query error",
            "detail_query": "complete OneIdentity publisher configuration",
            "details": "complete OneIdentity publisher configuration",
            "tsv": "complete OneIdentity publisher TSV configuration",
            "tempfile": "stub stage allocation error",
            "copy": "stub required archive copy error",
            "media": "stub required media missing",
            "worker": "stub pkg5srv access denied",
        }
        for registered, route in (
                ("svr4", "equal"), ("svr4", "downgrade"), ("ips", "downgrade")):
            for fault, reason in faults.items():
                with self.subTest(registered=registered, route=route, fault=fault):
                    completed, data = self.run_case(
                        registered=registered, route=route, fault=fault,
                    )
                    self.assert_rejected(completed, data, reason)
                    self.assertEqual(data["installed"]["vasclnt"]["system"], registered)

    def test_readable_unique_stage_precedes_migration_and_both_downgrades(self):
        for registered, route in (
                ("svr4", "equal"), ("svr4", "downgrade"), ("ips", "downgrade")):
            with self.subTest(registered=registered, route=route):
                completed, data = self.run_case(registered=registered, route=route)
                self.assert_success(completed)
                self.assertEqual(len(self.removals(data)),
                                 1 if registered == "svr4" else 0)
                self.assertTrue(all("pkgrm" in event["argv"]
                                    for event in self.removals(data)))
                self.assertEqual(data["installed"]["vasclnt"], {
                    "system": "ips", "version": TARGET_VERSION,
                })
                self.assertEqual(data["stages"], data["cleaned"])
                self.assertEqual(len(data["stages"]), 1)
                self.assertFalse(Path(data["stages"][0]).exists())
                self.assertEqual(len(data["worker_checks"]), 1)
                worker = data["worker_checks"][0]
                self.assertTrue(worker["read"])
                self.assertEqual(worker["directory_mode"], 0o755)
                self.assertEqual(worker["file_mode"], 0o644)
                self.assertEqual(worker["identity"], [
                    ["groups", []], ["gid", 4243], ["uid", 4242],
                ])
                commands = [event["argv"] for event in data["commands"]]
                worker_index = next(i for i, cmd in enumerate(commands)
                                    if len(cmd) == 4 and cmd[1] == "-c")
                # IPS downgrade has no removal. Worker access must still
                # precede EVERY package/publisher mutation, including install.
                for mutation in (self.removals(data) + self.publisher_mutations(data)
                                 + self.ips_installs(data)):
                    self.assertLess(worker_index, commands.index(mutation["argv"]),
                                    mutation)
                self.assertIn([
                    "pkg", "install", "--accept",
                    "pkg://OneIdentity/vasclnt@" + TARGET_VERSION,
                ], commands)
                self.assertEqual(
                    stat.S_IMODE(data["sandbox"].joinpath("private").stat().st_mode),
                    0o700,
                )
                self.assertEqual(stat.S_IMODE(data["old_archive"].stat().st_mode), 0o600)
                self.assertEqual(data["old_archive"].read_bytes(),
                                 b"pre-existing caller media\n")
                self.assertEqual(stat.S_IMODE(data["source"].stat().st_mode), 0o600)
                self.assertTrue(all(
                    event["args"].get("owner") == "root"
                    for event in data["events"]
                    if event["action"] in ("copy", "file")
                    and event["args"].get("state") != "absent"
                    and event["args"].get("dest", event["args"].get("path", ""))
                    .startswith(data["stages"][0])
                ))
                cleanup = next(i for i, event in enumerate(data["events"])
                               if event["action"] == "file"
                               and event["args"].get("state") == "absent")
                last_publisher = max(
                    i for i, event in enumerate(data["events"])
                    if event["action"] == "command"
                    and event.get("argv", [])[:2] == ["pkg", "set-publisher"]
                )
                self.assertGreater(cleanup, last_publisher)

    def test_downgrade_live_probes_precede_single_pkgrm(self):
        completed, data = self.run_case(route="downgrade")
        self.assert_success(completed)
        self.assertEqual(len(self.removals(data)), 1)
        self.assertIn("pkgrm", self.removals(data)[0]["argv"])
        commands = [event["argv"] for event in data["commands"]]
        worker = next(i for i, cmd in enumerate(commands)
                      if len(cmd) == 4 and cmd[1] == "-c")
        removal = commands.index(self.removals(data)[0]["argv"])
        for probe in (["pkg", "info", "vasclnt"], ["pkginfo", "vasclnt"]):
            # Ignore the cached version probes before preflight: the helper's
            # live probes must authorise migration, not follow remove.yml.
            probe_index = commands.index(probe, worker + 1)
            self.assertLess(worker, probe_index)
            self.assertLess(probe_index, removal)
        self.assertTrue(self.removals(data)[0]["task"].endswith(
            "migrate legacy SVR4 vasclnt to IPS"
        ))
        self.assertEqual(len(self.ips_installs(data)), 1)
        self.assertLess(removal, commands.index(self.ips_installs(data)[0]["argv"]))
        self.assertEqual(data["installed"]["vasclnt"], {
            "system": "ips", "version": TARGET_VERSION,
        })

    def test_ips_downgrade_installs_requested_version_without_uninstall(self):
        for linked in ("", LINKED_CHILD):
            with self.subTest(linked=linked):
                completed, data = self.run_case(
                    route="downgrade", registered="ips", linked=linked,
                )
                self.assert_success(completed)
                self.assertEqual(self.removals(data), [])
                self.assertEqual(len(self.ips_installs(data)), 1)
                self.assertEqual(self.ips_installs(data)[0]["argv"][-1],
                                 "pkg://OneIdentity/vasclnt@" + TARGET_VERSION)
                self.assertEqual(data["installed"]["vasclnt"], {
                    "system": "ips", "version": TARGET_VERSION,
                })
                self.assertIsNone(data["temp_origin"])
                self.assertEqual(data["stages"], data["cleaned"])

    def test_failed_ips_transitions_preserve_original_version_and_system(self):
        for route in ("upgrade", "downgrade"):
            for linked in ("", LINKED_CHILD):
                with self.subTest(route=route, linked=linked):
                    completed, data = self.run_case(
                        route=route, registered="ips", linked=linked,
                        fault="install", publisher_enabled=False,
                    )
                    self.assertNotEqual(completed.returncode, 0, completed.stdout)
                    self.assertIn("stub package install error", completed.stdout)
                    self.assertEqual(data["installed"], data["initial_installed"])
                    self.assertEqual(self.removals(data), [])
                    self.assertEqual(len(self.ips_installs(data)), 1)
                    self.assertFalse(data["publisher_enabled"])
                    self.assertIsNone(data["temp_origin"])
                    self.assertEqual(data["stages"], data["cleaned"])

    def test_direct_installs_pin_media_version_despite_newer_catalog(self):
        for route in ("install", "upgrade", "downgrade"):
            with self.subTest(route=route):
                completed, data = self.run_case(
                    route=route, registered="ips", linked="",
                    newer_catalog_version=NEWER_CATALOG_VERSION,
                )
                self.assert_success(completed)
                # The stub selects the newer catalog release for an
                # unversioned operand, rather than always forcing the media.
                self.assertEqual(data["installed"]["vasclnt"], {
                    "system": "ips", "version": TARGET_VERSION,
                })
                self.assertEqual(
                    [event["argv"] for event in self.ips_installs(data)], [[
                        "pkg", "install", "--accept", "-g",
                        str(data["old_archive"]),
                        "pkg://OneIdentity/vasclnt@" + TARGET_VERSION,
                    ]],
                )
                self.assertEqual(self.removals(data), [])
                self.assertEqual(self.publisher_mutations(data), [])

    def test_restore_enabled_state_origins_and_proxies_with_both_detail_labels(self):
        for label in ("Enabled", "Publisher enabled"):
            with self.subTest(label=label):
                completed, data = self.run_case(
                    publisher_enabled=False, enabled_label=label, detail_rc=3,
                )
                self.assert_success(completed)
                commands = [event["argv"] for event in self.publisher_mutations(data)]
                self.assertIn(["pkg", "set-publisher", "--enable", "OneIdentity"], commands)
                self.assertIn(["pkg", "set-publisher", "--disable", "OneIdentity"], commands)
                self.assertIn([
                    "pkg", "set-publisher", "--no-refresh", "--disable",
                    "-g", "https://packages.example.invalid/secondary/",
                    "--proxy", "http://proxy.example.invalid:8080", "OneIdentity",
                ], commands)
                self.assertFalse(data["publisher_enabled"])
                self.assertEqual(data["stages"], data["cleaned"])

    def test_new_publisher_is_unset_before_stage_cleanup(self):
        completed, data = self.run_case(publisher_exists=False)
        self.assert_success(completed)
        self.assertEqual(
            self.publisher_mutations(data)[-1]["argv"],
            ["pkg", "unset-publisher", "OneIdentity"],
        )
        self.assertEqual(data["stages"], data["cleaned"])

    def test_failed_install_still_restores_publisher_and_cleans_stage(self):
        completed, data = self.run_case(fault="install", publisher_enabled=False)
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertIn("stub package install error", completed.stdout)
        self.assertEqual(len(self.removals(data)), 1)
        self.assertFalse(data["publisher_enabled"])
        self.assertIsNone(data["temp_origin"])
        self.assertEqual(data["stages"], data["cleaned"])

    def test_stage_is_retained_only_while_publisher_may_still_use_it(self):
        for fault, exists in (("detach", True), ("unset", False), ("set_publisher", True)):
            with self.subTest(fault=fault):
                completed, data = self.run_case(fault=fault, publisher_exists=exists)
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertIn("Retaining", completed.stdout)
                self.assertEqual(data["cleaned"], [])
                self.assertTrue(Path(data["stages"][0], "archive.p5p").is_file())
                self.assertIsNotNone(data["temp_origin"])

    def test_failed_old_origin_restoration_does_not_leak_detached_stage(self):
        completed, data = self.run_case(fault="restore")
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertIn("could not restore OneIdentity origin", completed.stdout)
        self.assertIsNone(data["temp_origin"])
        self.assertEqual(data["stages"], data["cleaned"])
        restored = [event for event in self.publisher_mutations(data)
                    if any("packages.example.invalid" in arg for arg in event["argv"])]
        self.assertEqual(len(restored), 2)  # Both restorations attempted despite errors.

    def test_check_mode_probes_without_mutations_or_missing_tempfile_attributes(self):
        for route in ("equal", "downgrade"):
            with self.subTest(route=route):
                completed, data = self.run_case(route=route, check=True)
                self.assert_success(completed)
                self.assertEqual(self.removals(data), [])
                self.assertEqual(self.publisher_mutations(data), [])
                self.assertEqual(data["stages"], [])
                self.assertEqual(data["worker_checks"], [])
                commands = [event["argv"] for event in data["commands"]]
                for probe in (["pkg", "info", "vasclnt"], ["pkginfo", "-l", "vasclnt"],
                              ["pkginfo", "vasclnt"], ["pkg", "list-linked", "-H"]):
                    self.assertIn(probe, commands)
                self.assertEqual(commands.count(["pkg", "info", "vasclnt"]), 2)
                self.assertFalse(any(cmd[:2] == ["pkg", "install"] for cmd in commands))
                self.assertEqual(data["old_archive"].read_bytes(),
                                 b"pre-existing caller media\n")

    def test_check_mode_rejects_unsupported_publishers_and_missing_media(self):
        for fault, reason in (("ssl", "SSL client credentials"),
                              ("system", "SYSPUB=true"),
                              ("media", "stub required media missing")):
            with self.subTest(fault=fault):
                completed, data = self.run_case(fault=fault, check=True, route="downgrade")
                self.assert_rejected(completed, data, reason)

    def test_parent_self_and_unlinked_images_keep_direct_archive_install(self):
        for linked in ("", "zone:child parent /zones/parent/root\n"
                           "self self /zones/child/root\n"):
            with self.subTest(linked=linked):
                completed, data = self.run_case(linked=linked, fault="ssl")
                self.assert_success(completed)
                self.assertEqual(data["publisher_queries"], 0)
                self.assertEqual(data["stages"], [])
                self.assertEqual(len(self.removals(data)), 1)
                installs = [event["argv"] for event in self.ips_installs(data)]
                self.assertEqual(installs, [[
                    "pkg", "install", "--accept", "-g",
                    str(data["old_archive"]),
                    "pkg://OneIdentity/vasclnt@" + TARGET_VERSION,
                ]])

    def test_ips_compatibility_registration_does_not_trigger_pkgrm(self):
        completed, data = self.run_case(registered="ips", route="upgrade", linked="")
        self.assert_success(completed)
        self.assertEqual(self.removals(data), [])

    def test_absent_only_and_unchanged_ips_do_not_preflight_unused_media(self):
        for registered in ("svr4", "ips"):
            with self.subTest(registered=registered):
                completed, data = self.run_case(
                    state="absent", registered=registered, fault="media",
                )
                self.assert_success(completed)
                self.assertEqual(len(self.removals(data)), 1)
                self.assertEqual(data["publisher_queries"], 0)
                self.assertEqual(data["stages"], [])
                self.assertFalse(any(event["argv"][:2] == ["pkg", "list-linked"]
                                     for event in data["commands"]))
        completed, data = self.run_case(registered="ips", fault="media")
        self.assert_success(completed)
        self.assertEqual(self.removals(data), [])
        self.assertEqual(data["publisher_queries"], 0)

    def test_solaris10_transitions_keep_interactive_completed_svr4_outcomes(self):
        for route in ("upgrade", "downgrade"):
            for rc in (0, 2, 10, 20):
                with self.subTest(route=route, rc=rc):
                    completed, data = self.run_case(
                        major="10", route=route, svr4_rc=rc,
                    )
                    self.assert_success(completed)
                    self.assertEqual(len(self.removals(data)), 1)
                    commands = [event["argv"] for event in data["commands"]]
                    installs = [cmd for cmd in commands if "pkgadd" in cmd]
                    self.assertEqual(len(installs), 1)
                    self.assertLess(commands.index(self.removals(data)[0]["argv"]),
                                    commands.index(installs[0]))
                    self.assertFalse(any("-n" in cmd for cmd in commands))
                    self.assertFalse(any(cmd[0] == "pkg" for cmd in commands))
                    self.assertEqual(data["installed"]["vasclnt"], {
                        "system": "svr4", "version": TARGET_VERSION,
                    })
                    self.assertEqual(data["stages"], [])

    def test_second_package_cannot_reuse_first_packages_cleanup_markers(self):
        completed, data = self.run_case(
            packages=("vasclnt", "vasgp"), fault="second_publisher",
        )
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertIn("stub publisher query error", completed.stdout)
        self.assertEqual([event["argv"][-1] for event in self.removals(data)], ["vasclnt"])
        self.assertEqual(data["installed"]["vasgp"]["system"], "svr4")
        self.assertEqual(len(data["stages"]), 1)
        self.assertEqual(data["stages"], data["cleaned"])

    def test_registration_query_errors_fail_closed(self):
        for fault, reason in (("ips_probe", "stub IPS registration query error"),
                              ("svr4_probe", "stub SVR4 registration query error")):
            with self.subTest(fault=fault):
                completed, data = self.run_case(fault=fault)
                self.assert_rejected(completed, data, reason)


class SolarisTaskContractTests(unittest.TestCase):
    def test_both_ips_install_paths_keep_rc_zero_and_four_handling(self):
        installs = [
            task for task in walk_tasks(
                yaml.safe_load((SOLARIS / "install_package.yml").read_text())
            )
            if task.get("command", {}).get("cmd", "").startswith("pkg install ")
        ]
        self.assertEqual(len(installs), 2)
        for task in installs:
            with self.subTest(task=task["name"]):
                self.assertEqual(task["changed_when"], "pkg_install.rc == 0")
                self.assertEqual(task["failed_when"], [
                    "pkg_install.rc != 0", "pkg_install.rc != 4",
                ])

    def test_all_four_registration_probes_keep_check_mode_and_locale_guards(self):
        probes = []
        for filename in ("version.yml", "install_package.yml"):
            for task in walk_tasks(yaml.safe_load((SOLARIS / filename).read_text())):
                cmd = task.get("command", {}).get("cmd", "")
                if cmd.startswith(("pkg info ", "pkginfo ")):
                    probes.append(task)
        self.assertEqual(len(probes), 4)
        for task in probes:
            with self.subTest(task=task["name"]):
                self.assertIs(task["check_mode"], False)
                self.assertEqual(task["environment"], {"LC_ALL": "C"})
                self.assertIs(task["changed_when"], False)
                self.assertIs(task["failed_when"], False)

    def test_new_nested_loops_do_not_override_outer_package_item(self):
        for filename in ("install_preflight.yml", "install_package.yml"):
            for task in walk_tasks(yaml.safe_load((SOLARIS / filename).read_text())):
                if "loop" in task:
                    self.assertNotEqual(
                        task.get("loop_control", {}).get("loop_var", "item"), "item",
                        task["name"],
                    )


if __name__ == "__main__":
    unittest.main()
