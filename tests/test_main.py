"""Tests for the command-line entry point."""

import importlib
import io
import os
import sys
import tomllib
import unittest
from unittest import mock

from githost import githost


class AliasTest(unittest.TestCase):
    """Check the two-letter aliases select the right service."""

    def test_aliases(self):
        for alias, service in [("gh", githost.Github), ("gl", githost.Gitlab),
                               ("bb", githost.Bitbucket)]:
            argv = ["githost", alias, "-u", "alice", "repo-list"]
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(service, "list_repos") as list_repos:
                githost.main()
            list_repos.assert_called_once()



class ServiceCommandTest(unittest.TestCase):
    """Check the githost-gh, githost-gl and githost-bb commands."""

    def test_commands_select_their_service(self):
        for entry, service in [(githost.main_github, githost.Github),
                               (githost.main_gitlab, githost.Gitlab),
                               (githost.main_bitbucket, githost.Bitbucket)]:
            argv = ["githost-xx", "-u", "alice", "repo-list"]
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(service, "list_repos") as list_repos:
                entry()
            list_repos.assert_called_once()

    def test_missing_subcommand_is_a_usage_error(self):
        for entry in [lambda: githost.main(["gitlab"]), githost.main_gitlab]:
            with mock.patch.object(sys, "argv", ["githost-gl"]), \
                 mock.patch("sys.stderr", new_callable=io.StringIO) as err, \
                 self.assertRaises(SystemExit) as ctx:
                entry()
            self.assertEqual(ctx.exception.code, 2)
            self.assertIn("the following arguments are required: command", err.getvalue())

    def test_pyproject_scripts_resolve(self):
        path = os.path.join(os.path.dirname(__file__), "..", "pyproject.toml")
        with open(path, "rb") as fh:
            scripts = tomllib.load(fh)["project"]["scripts"]
        self.assertEqual(sorted(scripts),
                         ["githost", "githost-bb", "githost-gh", "githost-gl"])
        for target in scripts.values():
            module, _, attr = target.partition(":")
            self.assertTrue(callable(getattr(importlib.import_module(module), attr)), target)


if __name__ == "__main__":
    unittest.main()
