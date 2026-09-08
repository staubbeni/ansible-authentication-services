"""Safe action stubs for executing the production Solaris task graph.

No command is executed and no root privileges or Solaris installation is needed.
Filesystem actions use real modes/files, but only below the unittest's sandbox;
owner=root is recorded rather than chowning. tempfile's /var/tmp is mapped to a
searchable sibling of the restrictive caller directory. The production worker
probe is executed with only its identity-changing calls replaced.
"""

import builtins
import json
import os
import shlex
import shutil
import stat
import tempfile
import types

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)
        self.root = task_vars["solaris_test_root"]
        state_path = os.path.join(self.root, "state.json")
        with open(state_path) as handle:
            self.state = json.load(handle)
        self.args = dict(self._task.args)
        self.check = bool(self._task.check_mode)
        action = self._task.action.split(".")[-1]
        self.event = {
            "action": action,
            "task": self._task.get_name(),
            "args": self.args,
            "check": self.check,
        }
        self.state["events"].append(self.event)
        try:
            result = getattr(self, "stub_" + action)()
        except Exception as error:
            result = {
                "failed": True, "changed": False, "rc": 1,
                "msg": str(error), "stdout": "", "stderr": str(error),
            }
        finally:
            with open(state_path, "w") as handle:
                json.dump(self.state, handle)
        return result

    def safe_path(self, path):
        if os.path.commonpath([os.path.realpath(path), self.root]) != self.root:
            raise AssertionError("Action attempted to leave the test sandbox")
        return path

    @staticmethod
    def result(rc=0, stdout="", stderr=""):
        return {
            "changed": False, "rc": rc, "stdout": stdout,
            "stdout_lines": stdout.splitlines(), "stderr": stderr,
            "stderr_lines": stderr.splitlines(), "failed": rc != 0,
        }

    def stub_tempfile(self):
        assert self.args["state"] == "directory"
        assert self.args["path"] == "/var/tmp"
        assert self.args["prefix"] == "ansible-as-ips-"
        if self.check:
            return {"changed": False, "skipped": True}  # Deliberately no path.
        if self.state["fault"] == "tempfile":
            raise OSError("stub stage allocation error")
        path = tempfile.mkdtemp(
            prefix=self.args["prefix"],
            dir=os.path.join(self.root, "stage-root"),
        )
        self.state["stages"].append(path)
        return {"changed": True, "path": path}

    def stub_file(self):
        path = self.safe_path(self.args["path"])
        if self.check:
            return {"changed": not os.path.exists(path)}
        if self.args["state"] == "absent":
            assert path in self.state["stages"], "Cleanup did not own this path"
            assert self.state["temp_origin"] != path + "/archive.p5p", (
                "Cleanup deleted an archive still used by the publisher"
            )
            shutil.rmtree(path)
            self.state["cleaned"].append(path)
        else:
            assert self.args["state"] == "directory"
            os.makedirs(path, exist_ok=True)
            if "mode" in self.args:
                os.chmod(path, int(self.args["mode"], 8))
            self.event["mode"] = stat.S_IMODE(os.stat(path).st_mode)
        return {"changed": True}

    def stub_copy(self):
        path = self.safe_path(self.args["dest"])
        if "src" in self.args:
            source = self.safe_path(self.args["src"])
            if not os.path.isfile(source):
                raise OSError("stub required media missing")
        if self.check:
            return {"changed": True}
        if (self.state["fault"] == "copy"
                and os.path.dirname(path) in self.state["stages"]):
            raise OSError("stub required archive copy error")
        if "src" in self.args:
            shutil.copyfile(source, path)
        else:
            with open(path, "w") as handle:
                handle.write(self.args["content"])
        if "mode" in self.args:
            os.chmod(path, int(self.args["mode"], 8))
        self.event["mode"] = stat.S_IMODE(os.stat(path).st_mode)
        return {"changed": True}

    def worker_probe(self, script, path):
        """Execute the real probe without changing the test runner's identity."""
        self.safe_path(path)
        identity = []
        check = {"path": path, "identity": identity, "read": False}
        self.state["worker_checks"].append(check)

        def getpwnam(name):
            assert name == "pkg5srv"
            return types.SimpleNamespace(pw_uid=4242, pw_gid=4243)

        def lstat(filename):
            assert identity == [("groups", []), ("gid", 4243), ("uid", 4242)]
            return os.lstat(self.safe_path(filename))

        def worker_open(filename, mode):
            assert identity == [("groups", []), ("gid", 4243), ("uid", 4242)]
            assert filename == path and mode == "rb"
            # World access is sufficient for this deliberately 0755/0644 stage.
            # Walk REAL ancestors as well as the file, not just root's os.access.
            parent = os.path.dirname(path)
            while True:
                assert os.stat(parent).st_mode & stat.S_IXOTH, parent
                if parent == "/":
                    break
                parent = os.path.dirname(parent)
            assert os.stat(path).st_mode & stat.S_IROTH
            if self.state["fault"] == "worker":
                raise OSError("stub pkg5srv access denied")
            check["read"] = True
            check["directory_mode"] = stat.S_IMODE(
                os.stat(os.path.dirname(path)).st_mode
            )
            check["file_mode"] = stat.S_IMODE(os.stat(path).st_mode)
            return open(path, mode)

        def exit_probe(message):
            raise OSError(message)

        modules = {
            "os": types.SimpleNamespace(
                setgroups=lambda groups: identity.append(("groups", groups)),
                setgid=lambda gid: identity.append(("gid", gid)),
                setuid=lambda uid: identity.append(("uid", uid)),
                lstat=lstat,
            ),
            "pwd": types.SimpleNamespace(getpwnam=getpwnam),
            "stat": stat,
            "sys": types.SimpleNamespace(argv=["-c", path], exit=exit_probe),
        }

        def import_probe(name, *args, **kwargs):
            return modules[name]

        probe_builtins = dict(vars(builtins))
        probe_builtins.update(__import__=import_probe, open=worker_open)
        exec(compile(script, "<production pkg5srv probe>", "exec"),
             {"__builtins__": probe_builtins})
        return self.result()

    def stub_shell(self):
        return self.stub_command()

    def stub_command(self):
        # Match command/shell check mode: read-only tasks explicitly override it.
        if self.check:
            return {"changed": False, "skipped": True}
        argv = self.args.get("argv")
        if argv is None:
            argv = shlex.split(self.args.get("cmd", self.args.get("_raw_params")))
        self.event["argv"] = argv
        entry = {
            "argv": argv, "task": self._task.get_name(),
            "environment": self._task.environment,
        }
        self.state["commands"].append(entry)
        fault = self.state["fault"]

        if len(argv) == 4 and argv[1] == "-c":
            return self.worker_probe(argv[2], argv[3])

        if argv[:2] == ["pkg", "info"] or argv[0] == "pkginfo":
            package = argv[-1]
            installed = self.state["installed"][package]
            is_ips = argv[0] == "pkg"
            if fault == "ips_probe" and is_ips:
                return self.result(1, stderr="stub IPS registration query error")
            if fault == "svr4_probe" and not is_ips:
                return self.result(1, stderr="stub SVR4 registration query error")
            # pkginfo also succeeds for IPS compatibility registrations.
            present = (installed["system"] == "ips" if is_ips
                       else bool(installed["system"]))
            if present:
                label = "Version" if is_ips else "VERSION"
                return self.result(stdout="%s: %s\n" % (label, installed["version"]))
            return self.result(1, stderr=(
                "pkg: info: no packages matching %s installed" % package
                if is_ips else "ERROR: information for %s was not found" % package
            ))

        if argv[:2] == ["pkg", "list-linked"]:
            if fault == "linked":
                return self.result(1, stderr="stub linked discovery error")
            return self.result(stdout=self.state["linked"])

        if argv == ["pkg", "publisher", "-H", "-F", "tsv"]:
            self.state["publisher_queries"] += 1
            if (fault == "publisher"
                    or (fault == "second_publisher"
                        and self.state["publisher_queries"] == 2)):
                return self.result(1, stderr="stub publisher query error")
            if fault == "tsv":
                return self.result(stdout="OneIdentity\ttrue\n")
            if not self.state["publisher_exists"]:
                return self.result()
            syspub = "true" if fault == "system" else "false"
            return self.result(stdout="\n".join(
                "OneIdentity\ttrue\t%s\t%s\torigin\tonline\t%s\t%s"
                % (syspub, enabled, uri, proxy)
                for enabled, uri, proxy in self.state["origins"]
            ))

        if argv == ["pkg", "publisher", "OneIdentity"]:
            if fault == "details":
                return self.result(3, stdout="Publisher: OneIdentity\n")
            enabled = "Yes" if self.state["publisher_enabled"] else "No"
            credential = "/var/pkg/ssl/test-key" if fault == "ssl" else "None"
            output = ("Publisher: OneIdentity\n%s: %s\n"
                      "SSL Key: %s\nSSL Cert: None\n") % (
                          self.state["enabled_label"], enabled, credential,
                      )
            rc = 1 if fault == "detail_query" else self.state["detail_rc"]
            return self.result(rc, stdout=output)

        if "pkgrm" in argv or argv[:2] == ["pkg", "uninstall"]:
            package = argv[-1]
            installed = self.state["installed"][package]
            assert installed["system"], "Double removal of an absent package"
            expected = "svr4" if "pkgrm" in argv else "ips"
            assert installed["system"] == expected, "Removed with the wrong tool"
            installed.update(system="", version="")
            return self.result(self.state["svr4_rc"] if expected == "svr4" else 0)

        if "pkgadd" in argv or argv[:2] == ["pkg", "install"]:
            if fault == "install":
                return self.result(1, stderr="stub package install error")
            package, separator, requested_version = argv[-1].split("/")[-1].partition("@")
            version = requested_version or self.state["target_version"]
            # Model release selection only, not the full IPS solver. Adding
            # an archive with -g leaves newer configured catalogs competing;
            # only a version-qualified operand constrains the requested release.
            if argv[:2] == ["pkg", "install"] and "-g" in argv and not separator:
                version = self.state["newer_catalog_version"] or version
            self.state["installed"][package].update(
                system="svr4" if "pkgadd" in argv else "ips",
                version=version,
            )
            return self.result(self.state["svr4_rc"] if "pkgadd" in argv else 0)

        if argv[:2] == ["pkg", "set-publisher"]:
            if "-g" in argv:
                origin = argv[argv.index("-g") + 1]
                if os.path.dirname(origin) in self.state["stages"]:
                    self.state["temp_origin"] = origin
                    if fault == "set_publisher":
                        return self.result(1, stderr="stub partial publisher error")
                elif fault == "restore":
                    return self.result(1, stderr="stub original origin restore error")
            elif "-G" in argv:
                if fault == "detach":
                    return self.result(1, stderr="stub temporary origin cleanup error")
                self.state["temp_origin"] = None
            if "--enable" in argv:
                self.state["publisher_enabled"] = True
            if "--disable" in argv:
                self.state["publisher_enabled"] = False
            return self.result()

        if argv[:2] == ["pkg", "unset-publisher"]:
            if fault == "unset":
                return self.result(1, stderr="stub temporary publisher cleanup error")
            self.state["temp_origin"] = None
            return self.result()

        raise AssertionError("Unrecognised command; never execute it: %r" % argv)
