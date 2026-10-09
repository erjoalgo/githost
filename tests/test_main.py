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
    """Check the ggh, ggl and gbb commands."""

    def test_commands_select_their_service(self):
        for entry, service in [(githost.main_github, githost.Github),
                               (githost.main_gitlab, githost.Gitlab),
                               (githost.main_bitbucket, githost.Bitbucket)]:
            argv = ["gxx", "-u", "alice", "repo-list"]
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(service, "list_repos") as list_repos:
                entry()
            list_repos.assert_called_once()

    def test_missing_subcommand_prints_commands(self):
        for entry in [lambda: githost.main(["gitlab"]), githost.main_gitlab]:
            with mock.patch.object(sys, "argv", ["ggl"]), \
                 mock.patch("sys.stderr", new_callable=io.StringIO) as err:
                self.assertEqual(entry(), 0)
            for command in ["key-post", "repo-list", "repo-create", "ls-mr", "create-mr"]:
                self.assertIn(command, err.getvalue())

    def help_of(self, service):
        """Returns the help g<alias> prints without arguments."""
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertEqual(githost.main([], service=service), 0)
        return err.getvalue()

    def test_service_help_is_specific(self):
        gitlab = self.help_of(githost.Gitlab)
        self.assertIn("usage: ggl", gitlab)
        self.assertNotIn("{github", gitlab)
        self.assertIn("ls-mr", gitlab)
        self.assertIn("create-mr", gitlab)

        github = self.help_of(githost.Github)
        self.assertIn("usage: ggh", github)
        self.assertNotIn("ls-mr", github)
        self.assertNotIn("create-mr", github)

    def test_help_names_the_service(self):
        for service, display_name in [(githost.Github, "GitHub"), (githost.Gitlab, "GitLab"),
                                      (githost.Bitbucket, "Bitbucket")]:
            self.assertIn(f"A command-line interface to {display_name}.",
                          self.help_of(service))
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            githost.main([])
        self.assertIn("A command-line interface to git repository hosting services",
                      err.getvalue())

    def test_key_type_only_for_bitbucket(self):
        def key_post_help(argv, service=None):
            with mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
                 self.assertRaises(SystemExit):
                githost.main(argv, service=service)
            return out.getvalue()
        self.assertIn("--key-type", key_post_help(["key-post", "-h"], githost.Bitbucket))
        self.assertNotIn("--key-type", key_post_help(["key-post", "-h"], githost.Gitlab))
        self.assertIn("--key-type", key_post_help(["gitlab", "key-post", "-h"]))

    def test_unsupported_command_is_rejected_by_parser(self):
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err, \
             self.assertRaises(SystemExit) as ctx:
            githost.main(["ls-mr"], service=githost.Github)
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("invalid choice: 'ls-mr'", err.getvalue())

    def test_pyproject_scripts_resolve(self):
        path = os.path.join(os.path.dirname(__file__), "..", "pyproject.toml")
        with open(path, "rb") as fh:
            scripts = tomllib.load(fh)["project"]["scripts"]
        self.assertEqual(sorted(scripts),
                         ["gbb", "ggh", "ggl", "githost"])
        for target in scripts.values():
            module, _, attr = target.partition(":")
            self.assertTrue(callable(getattr(importlib.import_module(module), attr)), target)


if __name__ == "__main__":
    unittest.main()
