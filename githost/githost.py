#!/usr/bin/python3

"""A command-line interface to git repository hosting services"""

from __future__ import annotations

import argparse
import getpass
import importlib.metadata
import json
import logging
import os
import platform
import re
import subprocess
import sys
import time
import traceback
import urllib.parse

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Tuple, Type, overload

import requests

if TYPE_CHECKING:
    from typing import Literal

logger = logging.getLogger(__name__)
logging.basicConfig()

try:
    __version__ = importlib.metadata.version('githost')
except Exception:
    __version__ = f"unknown: {traceback.format_exc()}"

def interactive_edit(initial_contents: str) -> str:
    """Open an editor to interactively edit a text template."""
    tmp = os.path.expanduser("~/.githost.tmp")
    editor = os.getenv("VISUAL") or os.getenv("EDITOR") or "vi"
    with open(tmp, "w") as stream:
        print(initial_contents, file=stream)

    subprocess.call([editor, tmp])

    with open(tmp, "r") as fh:
        contents = fh.read()
        return contents

def read_choice(choices: Sequence[str], prompt: str = "select: ") -> str:
    """Prompt user for the index of their selection."""
    while True:
        print ("\n".join(f"{i}: {choice}"
                         for (i, choice) in enumerate(choices)))
        resp = input(prompt)
        try:
            idx = int(resp)
            return choices[idx]
        except Exception:
            pass

def git(*args: str) -> str:
    """Run a git command and return its stripped output."""
    return subprocess.check_output(["git", *args], text=True).strip()

def local_branch_exists(name: str) -> bool:
    """Whether the current git repo has a local branch with this name."""
    return subprocess.run(["git", "rev-parse", "-q", "--verify", f"refs/heads/{name}"],
                          stdout=subprocess.DEVNULL).returncode == 0

def local_branch_or_default(name: Optional[str]) -> str:
    """Returns the local branch name, or main, else master, when it's None.

    Exits if that branch doesn't exist locally."""
    candidates = [name] if name else ["main", "master"]
    branch = next((c for c in candidates if local_branch_exists(c)), None)
    if not branch:
        sys.exit(f"no local branch {' or '.join(candidates)}; pass --branch")
    return branch

def parse_remote_url(url: str) -> Tuple[Optional[str], str]:
    """Extract the host and project path, e.g. group/sub/proj, from a git remote url."""
    if "://" in url:
        parsed = urllib.parse.urlparse(url)
        host, path = parsed.hostname, parsed.path
    else:
        # scp-like syntax: git@host:group/proj.git
        host, path = url.split(":", 1)
        host = host.rsplit("@", 1)[-1]
    path = path.strip("/")
    return host, path[:-len(".git")] if path.endswith(".git") else path

@dataclass
class Auth:
    """Authentication information."""
    user: Optional[str]
    passwd: Optional[str]
    authinfo: Optional[str]


@dataclass(order=True)
class PrEvent:
    """A comment or submitted review on a pull request, ordered by time."""
    time: datetime
    author: str
    # comment:ID or review:ID, the ids show-pr prints
    event: str
    note: str = ""


class Service:
    """Base class holding the common implementation for interacting with a git-hosting service."""
    name: str
    alias: str
    display_name: str
    base: str

    def __init__(self, auth: Auth) -> None:
        self.auth = auth

    def read_authinfo(self) -> Optional[Auth]:
        """Try looking up auth details from the user's authinfo file."""
        auth = self.auth
        authinfo = auth.authinfo
        if authinfo and os.path.exists(authinfo):
            machine = self.api_host()
            # TODO(ealfonso) support changing token order
            login = re.escape(auth.user) if auth.user else ".*"
            pat = re.compile("^machine {} login ({}) password (.*)"
                             .format(re.escape(machine), login))
            try:
                with open(authinfo, "r") as fh:
                    lines = fh.read().split("\n")
            except IOError as ex:
                logger.error("failed to read .autinfo: %s", str(ex))
                return None
            for line in lines:
                m = pat.match(line)
                if m:
                    auth.user = m.group(1)
                    auth.passwd = m.group(2)
                    print(f"found {machine} password in {authinfo}")
                    return auth
        return None

    def api_host(self) -> str:
        """Extract the git-hosting service hostname."""
        hostname = urllib.parse.urlparse(self.base).hostname
        if not hostname:
            raise ValueError(f"no hostname in base url {self.base!r}; check --base-url")
        return hostname

    def write_authinfo(self, authinfo: Optional[str]) -> None:
        """Persist the gathered credentials into the user's authinfo."""
        user, passwd=self.user(), self.password()
        assert authinfo
        machine = self.api_host()
        with open(authinfo, "a") as fh:
            print(f"machine {machine} login {user} password {passwd}", file = fh)

    def user(self, prompt: str = "enter username: ") -> str:
        """Read or prompt for the service username."""
        if not self.auth.user and not self.read_authinfo():
            self.auth.user = input(prompt)
        assert self.auth.user is not None
        return self.auth.user

    def password(self, prompt: str = "enter password: ") -> str:
        """Read or prompt for the service password or token."""
        if not self.auth.passwd and not self.read_authinfo():
            if not sys.stdin.isatty():
                login = f"login {self.auth.user}" if self.auth.user else "a login"
                sys.exit(f"no token for {login} at {self.api_host()} in "
                         f"{self.auth.authinfo}, and no terminal to ask for one")
            self.auth.passwd = getpass.getpass(prompt)
            authinfo = self.auth.authinfo
            passwd = self.auth.passwd
            if read_choice(["yes", "no"],
                           prompt=f"write to {authinfo}? ") == "yes":
                self.write_authinfo(authinfo)
            self.auth.passwd = passwd
        assert self.auth.passwd is not None
        return self.auth.passwd

    def req_auth(self, req: requests.Request, prompt: Optional[str] = None) -> None:
        """Fill in the request's authentication details."""
        kwargs = {"prompt": prompt} if prompt else {}
        # uses basic auth by default
        req.auth = (self.user(), self.password(**kwargs))

    @overload
    def req_send(self, req: requests.Request, add_auth: bool = ..., print_json: bool = ...,
                 missing_ok: Literal[False] = ...) -> requests.Response: ...

    @overload
    def req_send(self, req: requests.Request, add_auth: bool = ..., print_json: bool = ...,
                 *, missing_ok: bool) -> Optional[requests.Response]: ...

    def req_send(self, req: requests.Request, add_auth: bool = True, print_json: bool = True,
                 missing_ok: bool = False) -> Optional[requests.Response]:
        """Send the request after filling in auth details and parses the response.

        Raises on an HTTP error. With missing_ok, a 404 returns None instead."""
        if not urllib.parse.urlparse(req.url).hostname:
            req.url = self.base + req.url
        if add_auth:
            self.req_auth(req)
        logger.debug("%s %s:\n%s\n%s\n%s", req.method, req.url, req.json, req.data, req.params)
        resp = requests.Session().send(req.prepare())
        if missing_ok and resp.status_code == 404:
            return None
        if not resp.ok:
            print (resp.text)
            resp.raise_for_status()
        if print_json:
            print (json.dumps(resp.json(), indent=4))
        return resp

    def git_add_remote(self, name: str, url: str) -> None:
        """Register the current githost service locally as a git remote."""
        cmd = ["git", "remote", "add", name, url]
        subprocess.run(cmd, check = True)

    def git_push_as_user(self, remote: str, branch: str) -> None:
        """Push a branch authenticated as this user and token.

        Bypasses git's configured credential helper, which may hold another
        account's token (e.g. a restricted agent's); the token is passed
        through the environment, not argv."""
        helper = f"!f() {{ echo username={self.user()}; echo password=$GFJ_TOKEN; }}; f"
        subprocess.run(["git", "-c", "credential.helper=", "-c", f"credential.helper={helper}",
                        "push", remote, branch],
                       env=dict(os.environ, GFJ_TOKEN=self.password()), check=True)

    def repo_name(self) -> str:
        """Returns the repository name."""
        cand = os.path.basename(os.getcwd())
        repo_name = input(f"repo name (default {cand}): ")
        return repo_name or cand

class Github(Service):
    """Manage the interaction with a Github repository host."""
    name = "github"
    display_name = "GitHub"
    alias = "gh"
    base = "https://api.github.com"

    TOKEN_URL = "https://github.com/settings/tokens"

    def __init__(self, auth: Auth) -> None:
        super().__init__(auth)
        self.fingerprints = """
        These are GitHub's public key fingerprints (in hexadecimal format):

16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48 (RSA)
ad:1c:08:a4:40:e3:6f:9c:f5:66:26:5d:4b:33:5d:8c (DSA)
These are the SHA256 hashes shown in OpenSSH 6.8 and newer (in base64 format):

SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8 (RSA)
SHA256:br9IjFspm1vxR3iA35FWE+4VTyz1hYVLIE2t1/CeyWQ (DSA)
        """

    def req_auth(self, req: requests.Request, prompt: Optional[str] = None) -> None:
        super().req_auth(
            req,
            prompt=f"enter github token ({self.TOKEN_URL}): ")
        req.headers["User-Agent"] = "anon"
        req.headers["Authorization"] = f"token {self.auth.passwd}"

    # TODO(ealfonso) rename to key_post
    def post_key(self, pubkey_path: str, pubkey_label: str, **kwargs: Any) -> None:
        """Post the given ssh public key to github."""
        del kwargs
        with open(pubkey_path, "r") as fh:
            pubkey = fh.read()
        data = {"key": pubkey, "title": pubkey_label}
        url = "/user/keys"
        req = requests.Request("POST", url, json=data)
        self.req_send(req)

    def repo_create(self, repo_name: str, description: Optional[str], private: bool = True,
                    **kwargs: Any) -> None:
        """Create a github repo with the given name and description."""
        del kwargs
        self.ensure_on_git_repo_directory()
        repo_name = self.repo_name()
        if not description:
            description = interactive_edit(f"# enter {repo_name} description").strip()

        data = {"name": repo_name,
                "description": description,
                "private": private,
                "has_issues": True,
                "has_projects": True,
                "has_wiki": True}
        url = "/user/repos"
        req = requests.Request("POST", url, json=data)
        resp = self.req_send(req)
        # TODO(ejalfonso) get clone_url from resp
        del resp
        clone_url = f"ssh://git@github.com/{self.user()}/{repo_name}"
        self.git_add_remote("github", clone_url)

    @staticmethod
    def ensure_on_git_repo_directory() -> None:
        """Make sure we're on a git repo directory."""
        subprocess.check_output(["git", "status"])

    def list_repos(self, **kwargs: Any) -> None:
        """List remote repositories."""
        del kwargs
        self.req_send(requests.Request("GET", "/user/repos"))


class Bitbucket(Service):
    """Manage the interaction with a Bitbucket repository host."""
    name = "bitbucket"
    display_name = "Bitbucket"
    alias = "bb"
    base = "https://api.bitbucket.org/2.0"
    # base = "http://localhost:1231"

    def post_key(self, pubkey_path: str, pubkey_label: str, key_type: Optional[str] = None,
                 repo_name: Optional[str] = None, **kwargs: Any) -> None:
        """Post the public ssh key to github."""
        del kwargs
        with open(pubkey_path, "r") as fh:
            pubkey = fh.read().strip()

        key_types = ("deploy", "ssh")
        key_type = key_type or read_choice(key_types)
        if not key_type in key_types:
            key_types_str = ",".join(key_types)
            raise Exception(f"Must specificy key type: {key_types_str}")

        data = {"key": pubkey, "label": pubkey_label}
        if key_type == "deploy":
            repo_name = self.repo_name()
            # if not repo_name:
                # raise Exception("Must specify repo name for deploy key post")
            url = f"/repositories/{self.user()}/{repo_name}/deploy-keys"
        elif key_type == "ssh":
            url = f"/users/{self.user()}/ssh-keys"
        else:
            raise Exception(f"unknown key type: {key_type}")

        req = requests.Request("POST", url, json=data)
        self.req_send(req)

    def list_repos(self, **kwargs: Any) -> None:
        """List the repos under the github account."""
        del kwargs
        url = f"/repositories/{self.user()}"
        req = requests.Request("GET", url)
        self.req_send(req)

    def repo_create(self, repo_name: str, description: Optional[str], private: bool = True,
                    **kwargs: Any) -> None:
        """Create the given repo on Bitbucket."""
        del kwargs
        repo_name = self.repo_name()
        if not description:
            description = interactive_edit(f"# enter {repo_name} description").strip()

        data = {
            # "project": {"key": repo_name},
            "description": description,
            "scm": "git",
            "private": private}
        url = f"/repositories/{self.user()}/{repo_name}"
        req = requests.Request("POST", url, json=data)
        resp = self.req_send(req)
        del resp
        # TODO(ejalfonso) get url from resp
        clone_url = f"ssh://git@bitbucket.com/{self.user()}/{repo_name}"
        self.git_add_remote("bitbucket", clone_url)

class Gitlab(Service):
    """Manage the interaction with a Gitlab repository host."""
    name = "gitlab"
    display_name = "GitLab"
    alias = "gl"
    base = "https://gitlab.com/api/v4"

    def token_url(self) -> str:
        """Returns the url where a personal access token can be created."""
        return f"https://{self.api_host()}/-/user_settings/personal_access_tokens"

    def req_auth(self, req: requests.Request, prompt: Optional[str] = None) -> None:
        super().req_auth(
            req,
            prompt=f"enter gitlab token with api scope ({self.token_url()}): ")
        # gitlab's API authenticates with a token header, not basic auth
        req.auth = None
        req.headers["PRIVATE-TOKEN"] = self.auth.passwd

    def post_key(self, pubkey_path: str, pubkey_label: str, **kwargs: Any) -> None:
        """Post the given ssh public key to gitlab."""
        del kwargs
        with open(pubkey_path, "r") as fh:
            pubkey = fh.read().strip()
        data = {"key": pubkey, "title": pubkey_label}
        req = requests.Request("POST", "/user/keys", json=data)
        self.req_send(req)

    def list_repos(self, **kwargs: Any) -> None:
        """List the projects owned by the gitlab user."""
        del kwargs
        req = requests.Request("GET", "/projects", params={"owned": "true"})
        self.req_send(req)

    def repo_create(self, repo_name: str, description: Optional[str], private: bool = True,
                    **kwargs: Any) -> None:
        """Create a gitlab project with the given name and description."""
        del kwargs
        Github.ensure_on_git_repo_directory()
        if not description:
            description = interactive_edit(f"# enter {repo_name} description").strip()

        data = {"name": repo_name,
                "description": description,
                "visibility": "private" if private else "public"}
        req = requests.Request("POST", "/projects", json=data)
        resp = self.req_send(req)
        clone_url = resp.json()["ssh_url_to_repo"]
        self.git_add_remote("gitlab", clone_url)

    def project_id(self, remote: Optional[str] = None) -> str:
        """Returns the url-encoded gitlab project path of the current repo.

        Defaults to the "gitlab" remote if it exists, otherwise "origin"."""
        if not remote:
            remote = "gitlab" if "gitlab" in git("remote").split() else "origin"
        host, path = parse_remote_url(git("remote", "get-url", remote))
        if host != self.api_host():
            sys.exit(f"remote {remote} is on {host}, not {self.api_host()}: "
                     "pick a gitlab remote with -R, or pass -b for a self-hosted gitlab")
        return urllib.parse.quote(path, safe="")

    def get_all(self, url: str, params: Optional[Dict[str, Any]] = None) -> List[Any]:
        """GET every page of a gitlab list endpoint."""
        params = dict(params or {}, per_page=100)
        items: List[Any] = []
        page: Optional[str] = "1"
        while page:
            params["page"] = page
            req = requests.Request("GET", url, params=dict(params))
            resp = self.req_send(req, print_json=False)
            items.extend(resp.json())
            page = resp.headers.get("X-Next-Page")
        return items

    def get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """GET a gitlab resource, or None if it does not exist."""
        req = requests.Request("GET", url, params=params)
        resp = self.req_send(req, print_json=False, missing_ok=True)
        return None if resp is None else resp.json()

    def mr_list(self, **kwargs: Any) -> None:
        """List the user's open and merged merge requests across all projects,
        followed by the branches they pushed to that have neither, as MR null.

        The date is when the MR was last updated, or the branch last committed to."""
        del kwargs
        has_mr = set()
        for state in ("opened", "merged"):
            params = {"state": state, "scope": "created_by_me"}
            for mr in self.get_all("/merge_requests", params):
                has_mr.add((mr["source_project_id"], mr["source_branch"]))
                draft = "[draft] " if mr.get("draft") else ""
                print(f"!{mr['iid']}\t{state}\t{mr['updated_at'][:10]}\t{mr['web_url']}"
                      f"\t{mr['source_branch']}\t{draft}{mr['title']}")

        pushed = dict.fromkeys(
            (event["project_id"], event["push_data"]["ref"])
            for event in self.get_all("/events", {"action": "pushed"})
            if event["push_data"]["ref_type"] == "branch")
        projects: Dict[Any, Any] = {}
        for project_id, ref in pushed:
            if (project_id, ref) in has_mr:
                continue
            if project_id not in projects:
                projects[project_id] = self.get(f"/projects/{project_id}")
            project = projects[project_id]
            if not project or ref == project["default_branch"]:
                continue
            quoted_ref = urllib.parse.quote(ref, safe="")
            branch = self.get(f"/projects/{project_id}/repository/branches/{quoted_ref}")
            if not branch:
                continue
            commit = branch["commit"]
            print(f"null\t-\t{commit['committed_date'][:10]}\t{branch['web_url']}"
                  f"\t{ref}\t{commit['title']}")

    def mr_create(self, remote: Optional[str] = None, source_branch: Optional[str] = None,
                  target_branch: Optional[str] = None, title: Optional[str] = None,
                  description: Optional[str] = None, **kwargs: Any) -> None:
        """Open a merge request for an already-pushed branch.

        Defaults to the current branch, the project's default branch as the
        target, and the last commit's message as the title and description."""
        del kwargs
        project = self.project_id(remote)
        source_branch = source_branch or git("rev-parse", "--abbrev-ref", "HEAD")
        if not target_branch:
            req = requests.Request("GET", f"/projects/{project}")
            target_branch = self.req_send(req, print_json=False).json()["default_branch"]
        if not title:
            message = interactive_edit(git("log", "-1", "--format=%B", source_branch))
            title, _, body = message.strip().partition("\n")
            description = description or body.strip()

        data = {"source_branch": source_branch,
                "target_branch": target_branch,
                "title": title,
                "description": description or ""}
        req = requests.Request("POST", f"/projects/{project}/merge_requests", json=data)
        resp = self.req_send(req, print_json=False)
        print(resp.json()["web_url"])

class Forgejo(Service):
    """Manage the interaction with a Forgejo instance.

    Defaults to a private instance on localhost; pass -b for another one."""
    name = "forgejo"
    display_name = "Forgejo"
    alias = "fj"
    base = "http://localhost:3123/api/v1"

    def web_url(self) -> str:
        """Returns the instance's web root, e.g. http://localhost:3123."""
        return self.base[:-len("/api/v1")] if self.base.endswith("/api/v1") else self.base

    def req_auth(self, req: requests.Request, prompt: Optional[str] = None) -> None:
        super().req_auth(
            req,
            prompt=f"enter forgejo token ({self.web_url()}/user/settings/applications): ")
        req.auth = None
        req.headers["Authorization"] = f"token {self.auth.passwd}"

    def get_all(self, url: str, params: Optional[Dict[str, Any]] = None) -> List[Any]:
        """GET every page of a forgejo list endpoint."""
        items: List[Any] = []
        next_req: Optional[requests.Request] = requests.Request(
            "GET", url, params=dict(params or {}, limit=50))
        while next_req:
            resp = self.req_send(next_req, print_json=False)
            items.extend(resp.json())
            next_url = resp.links.get("next", {}).get("url")
            next_req = requests.Request("GET", next_url) if next_url else None
        return items

    def get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """GET a forgejo resource."""
        req = requests.Request("GET", url, params=params)
        return self.req_send(req, print_json=False).json()

    def post_key(self, pubkey_path: str, pubkey_label: str, **kwargs: Any) -> None:
        """Post the given ssh public key to forgejo."""
        del kwargs
        with open(pubkey_path, "r") as fh:
            pubkey = fh.read().strip()
        data = {"key": pubkey, "title": pubkey_label}
        req = requests.Request("POST", "/user/keys", json=data)
        self.req_send(req)

    def list_repos(self, **kwargs: Any) -> None:
        """List the repos the forgejo user can access."""
        del kwargs
        print(json.dumps(self.get_all("/user/repos"), indent=4))

    def repo_create(self, repo_name: str, description: Optional[str], private: bool = True,
                    **kwargs: Any) -> None:
        """Create a forgejo repo and add it as the "forgejo" git remote."""
        del kwargs
        Github.ensure_on_git_repo_directory()
        data = {"name": repo_name,
                "description": description or "",
                "private": private}
        req = requests.Request("POST", "/user/repos", json=data)
        resp = self.req_send(req, print_json=False)
        repo = resp.json()
        self.git_add_remote("forgejo", repo["clone_url"])
        print(repo["html_url"])

    def collaborator_add(self, users: List[str], remote: Optional[str] = None,
                         permission: str = "write", **kwargs: Any) -> None:
        """Add users as collaborators, or change their permission if they already are."""
        del kwargs
        repo = self.repo_path(remote)
        for user in users:
            req = requests.Request("PUT", f"/repos/{repo}/collaborators/{user}",
                                   json={"permission": permission})
            self.req_send(req, print_json=False)
            print(f"{user}: {permission}")

    def branch_protect(self, branch: str, remote: Optional[str] = None,
                       **kwargs: Any) -> None:
        """Protect a branch so only you can push to it or merge.

        Safe to re-run: an existing rule for the branch is updated."""
        del kwargs
        repo = self.repo_path(remote)
        me = self.get("/user")["login"]
        data: Dict[str, Any] = {"enable_push": True,
                                "enable_push_whitelist": True,
                                "push_whitelist_usernames": [me],
                                "enable_merge_whitelist": True,
                                "merge_whitelist_usernames": [me]}
        rule_url = f"/repos/{repo}/branch_protections"
        quoted = urllib.parse.quote(branch, safe="")
        existing = self.req_send(requests.Request("GET", f"{rule_url}/{quoted}"),
                                 print_json=False, missing_ok=True)
        if existing:
            req = requests.Request("PATCH", f"{rule_url}/{quoted}", json=data)
        else:
            req = requests.Request("POST", rule_url, json=dict(data, rule_name=branch))
        self.req_send(req, print_json=False)
        print(f"{branch}: only {me} can push or merge")

    def repo_publish(self, repo_name: str, description: Optional[str] = None,
                     collaborator: Optional[List[str]] = None, branch: Optional[str] = None,
                     **kwargs: Any) -> None:
        """Create the repo, add collaborators, push a branch as you, and protect it.

        Safe to re-run: an existing forgejo remote skips the create step, and
        the other steps are idempotent."""
        del kwargs
        branch = local_branch_or_default(branch)
        if self.name in git("remote").split():
            print(f"{self.name} remote exists, not creating the repo")
        else:
            self.repo_create(repo_name, description)
        if collaborator:
            self.collaborator_add(collaborator)
        self.git_push_as_user(self.name, branch)
        self.branch_protect(branch)

    def repo_path(self, remote: Optional[str] = None) -> str:
        """Returns owner/repo of the current repo on forgejo.

        Defaults to the "forgejo" remote if it exists, otherwise "origin"."""
        if not remote:
            remote = "forgejo" if "forgejo" in git("remote").split() else "origin"
        host, path = parse_remote_url(git("remote", "get-url", remote))
        if host != self.api_host():
            sys.exit(f"remote {remote} is on {host}, not {self.api_host()}: "
                     "pick a forgejo remote with -R, or pass -b for another instance")
        return path

    def pr_list(self, remote: Optional[str] = None, state: str = "open",
                **kwargs: Any) -> None:
        """List the current repo's pull requests, most recently updated first."""
        del kwargs
        repo = self.repo_path(remote)
        prs = self.get_all(f"/repos/{repo}/pulls", {"state": state, "sort": "recentupdate"})
        for pr in prs:
            pr_state = "merged" if pr.get("merged") else pr["state"]
            draft = "[draft] " if pr.get("draft") else ""
            print(f"#{pr['number']}\t{pr_state}\t{pr['updated_at'][:10]}\t{pr['html_url']}"
                  f"\t{pr['head']['ref']}\t{draft}{pr['title']}")

    def pr_create(self, remote: Optional[str] = None, source_branch: Optional[str] = None,
                  target_branch: Optional[str] = None, title: Optional[str] = None,
                  description: Optional[str] = None, **kwargs: Any) -> None:
        """Open a pull request for an already-pushed branch.

        Defaults to the current branch, the repo's default branch as the
        target, and the last commit's message as the title and description."""
        del kwargs
        repo = self.repo_path(remote)
        source_branch = source_branch or git("rev-parse", "--abbrev-ref", "HEAD")
        if not target_branch:
            target_branch = self.get(f"/repos/{repo}")["default_branch"]
        if not title:
            message = interactive_edit(git("log", "-1", "--format=%B", source_branch))
            title, _, body = message.strip().partition("\n")
            description = description or body.strip()

        data = {"head": source_branch,
                "base": target_branch,
                "title": title,
                "body": description or ""}
        req = requests.Request("POST", f"/repos/{repo}/pulls", json=data)
        resp = self.req_send(req, print_json=False)
        print(resp.json()["html_url"])

    def pr_number(self, repo: str, number: Optional[int]) -> int:
        """Returns the given PR number, or that of the open PR for the current checkout.

        An open PR matches if its head branch, in this repo, is the current
        branch, or its head commit is the current commit (e.g. on a detached
        HEAD). More than one match is an error rather than a guess."""
        if number:
            return number
        branch = git("rev-parse", "--abbrev-ref", "HEAD")
        commit = git("rev-parse", "HEAD")
        matches = [pr for pr in self.get_all(f"/repos/{repo}/pulls", {"state": "open"})
                   if pr["head"]["sha"] == commit
                   or (pr["head"]["ref"] == branch
                       and (pr["head"].get("repo") or {}).get("full_name", repo) == repo)]
        if len(matches) == 1:
            return int(matches[0]["number"])
        if matches:
            numbers = ", ".join(f"#{pr['number']}" for pr in matches)
            sys.exit(f"several open pull requests match {branch} at {commit[:10]}: "
                     f"{numbers}; pass the PR number")
        sys.exit(f"no open pull request for {branch} at {commit[:10]}; pass the PR number")

    def pr_show(self, remote: Optional[str] = None, number: Optional[int] = None,
                **kwargs: Any) -> None:
        """Print a pull request with its comments, reviews and inline review comments.

        Defaults to the open PR for the current branch. Inline comments show
        file:line, the end of the diff hunk they're on, and whether they're
        resolved or on outdated code."""
        del kwargs
        repo = self.repo_path(remote)
        number = self.pr_number(repo, number)
        pr = self.get(f"/repos/{repo}/pulls/{number}")
        pr_state = "merged" if pr.get("merged") else pr["state"]
        print(f"#{number} {pr_state}: {pr['title']}\n{pr['html_url']}\n"
              f"{pr['head']['ref']} -> {pr['base']['ref']}")
        if pr.get("body"):
            print(f"\n{pr['body']}")

        for comment in self.get_all(f"/repos/{repo}/issues/{number}/comments"):
            print(f"\n--- comment {comment['id']} by {comment['user']['login']}"
                  f" at {comment['created_at']}\n{comment['body']}")

        for review in self.get_all(f"/repos/{repo}/pulls/{number}/reviews"):
            comments = []
            if review.get("comments_count"):
                comments = self.get(
                    f"/repos/{repo}/pulls/{number}/reviews/{review['id']}/comments")
            if not review.get("body") and not comments:
                continue
            stale = " (stale)" if review.get("stale") else ""
            print(f"\n--- review {review['id']} by {review['user']['login']}, "
                  f"{review['state']}{stale}, at {review['submitted_at']}")
            if review.get("body"):
                print(review["body"])
            for comment in comments:
                line = comment.get("position") or comment.get("original_position")
                notes = []
                if comment.get("resolver"):
                    notes.append(f"resolved by {comment['resolver']['login']}")
                if not comment.get("position"):
                    notes.append("outdated")
                note = f" ({', '.join(notes)})" if notes else ""
                hunk = "\n".join(comment.get("diff_hunk", "").splitlines()[-4:])
                print(f"\n  > comment {comment['id']} on {comment['path']}:{line}{note}")
                if hunk:
                    print("    " + hunk.replace("\n", "\n    "))
                print("  " + comment["body"].replace("\n", "\n  "))

    @staticmethod
    def pr_activity(comments: List[Any], reviews: List[Any]) -> List[PrEvent]:
        """Returns each of a PR's comments and submitted reviews as an event.

        The time is the latest of creation and last edit, so edits count as activity."""
        def when(item: Any, *keys: str) -> datetime:
            return max(datetime.fromisoformat(item[key]) for key in keys if item.get(key))
        activity = []
        for comment in comments:
            activity.append(PrEvent(when(comment, "created_at", "updated_at"),
                                    comment["user"]["login"], f"comment:{comment['id']}"))
        for review in reviews:
            if review["state"] == "PENDING":
                continue
            activity.append(PrEvent(when(review, "submitted_at", "updated_at"),
                                    review["user"]["login"], f"review:{review['id']}",
                                    f" ({review['state']})"))
        return activity

    def pr_unreplied(self, repo: str, number: int, me: str,
                     comments: List[Any], reviews: List[Any]) -> List[str]:
        """Returns a line for each comment by others that none of ours answers.

        comment-pr -r starts a reply with "Re: USER's comment ID", so a
        comment counts as replied once one of ours names its id; edits to
        either comment don't change that. Covers general comments and
        inline review comments, skipping resolved ones."""
        replied = {int(match) for comment in comments if comment["user"]["login"] == me
                   for match in re.findall(r"^Re: \S+'s comment (\d+)\b",
                                           comment["body"], re.MULTILINE)}
        theirs = [comment for comment in comments if comment["user"]["login"] != me]
        for review in reviews:
            if review["state"] != "PENDING" and review.get("comments_count"):
                theirs += [comment for comment in self.get(
                    f"/repos/{repo}/pulls/{number}/reviews/{review['id']}/comments")
                           if comment["user"]["login"] != me and not comment.get("resolver")]
        lines = []
        for comment in theirs:
            if comment["id"] in replied:
                continue
            where = (f" on {comment['path']}:"
                     f"{comment.get('position') or comment.get('original_position')}"
                     if comment.get("path") else "")
            lines.append(f"#{number}: unreplied comment {comment['id']}"
                         f" by {comment['user']['login']}{where}")
        return lines

    def pr_wait(self, remote: Optional[str] = None, number: Optional[int] = None,
                interval: float = 30, since: Optional[str] = None, **kwargs: Any) -> None:
        """Block until a PR gets feedback after a given event, or after our own last one.

        Feedback is a comment or submitted review by anyone but the token's
        user. By default it must come after our latest comment or review, or
        any feedback counts if we have none, so feedback left before wait-pr
        started is not missed. since names the event to wait after instead,
        as comment:ID or review:ID (e.g. to skip feedback that needed no
        reply), or "none" for any feedback. Also returns when the PR is
        closed or merged, or while any comment by others is unreplied (see
        pr_unreplied), however old, so comments that arrive while we answer
        others aren't lost behind our replies. Network errors are retried every interval, so a
        restart of the server doesn't end the wait."""
        del kwargs
        repo = self.repo_path(remote)
        number = self.pr_number(repo, number)
        me = self.get("/user")["login"]
        # Earlier than any event: the cutoff when all feedback counts.
        no_cutoff = datetime.min.replace(tzinfo=timezone.utc)
        since_time: Optional[datetime] = None
        while True:
            try:
                pr = self.get(f"/repos/{repo}/pulls/{number}")
                if pr["state"] != "open":
                    print(f"#{number} is {'merged' if pr.get('merged') else pr['state']}")
                    return
                comments = self.get_all(f"/repos/{repo}/issues/{number}/comments")
                reviews = self.get_all(f"/repos/{repo}/pulls/{number}/reviews")
                activity = self.pr_activity(comments, reviews)
                unreplied = self.pr_unreplied(repo, number, me, comments, reviews)
            except (requests.ConnectionError, requests.Timeout) as err:
                print(f"#{number}: {err}; retrying in {interval:g}s", file=sys.stderr)
                time.sleep(interval)
                continue
            if since_time is None:
                if since == "none":
                    since_time = no_cutoff
                elif since:
                    times = [item.time for item in activity if item.event == since]
                    if not times:
                        sys.exit(f"no event {since} on PR #{number}: expected comment:ID or "
                                 "review:ID as shown by show-pr, or none")
                    since_time = times[0]
                else:
                    since_time = max((item.time for item in activity if item.author == me),
                                     default=no_cutoff)
            feedback = sorted(item for item in activity
                              if item.author != me and item.time > since_time)
            if feedback or unreplied:
                for item in feedback:
                    print(f"#{number}: {item.event}{item.note} by {item.author}"
                          f" at {item.time.isoformat()}")
                for line in unreplied:
                    print(line)
                if feedback:
                    print(f"to wait for more: wait-pr {number} --since {feedback[-1].event}")
                return
            time.sleep(interval)

    def pr_find_comment(self, repo: str, number: int, comment_id: int) -> Any:
        """Returns the PR's general or inline review comment with the given id.

        The API has no endpoint to get an inline comment by id, so this
        searches the PR's comments, then each review's."""
        for comment in self.get_all(f"/repos/{repo}/issues/{number}/comments"):
            if comment["id"] == comment_id:
                return comment
        for review in self.get_all(f"/repos/{repo}/pulls/{number}/reviews"):
            if not review.get("comments_count"):
                continue
            for comment in self.get(
                    f"/repos/{repo}/pulls/{number}/reviews/{review['id']}/comments"):
                if comment["id"] == comment_id:
                    return comment
        sys.exit(f"no comment {comment_id} on PR #{number}")

    def pr_comment(self, remote: Optional[str] = None, number: Optional[int] = None,
                   message: Optional[str] = None, reply_to: Optional[int] = None,
                   **kwargs: Any) -> None:
        """Comment on a pull request, optionally quoting the comment it replies to.

        A reply to an inline review comment is posted on the PR, quoting the
        comment's file:line and text, since the API can't post into its thread."""
        del kwargs
        repo = self.repo_path(remote)
        number = self.pr_number(repo, number)
        quote = ""
        if reply_to:
            target = self.pr_find_comment(repo, number, reply_to)
            where = (f" on `{target['path']}:"
                     f"{target.get('position') or target.get('original_position')}`"
                     if target.get("path") else "")
            quoted = "\n".join(f"> {line}" for line in target["body"].splitlines())
            quote = (f"Re: {target['user']['login']}'s comment {target['id']}{where}:\n"
                     f"{quoted}\n\n")
        if not message:
            message = interactive_edit(f"{quote}").strip()
        else:
            message = quote + message
        req = requests.Request("POST", f"/repos/{repo}/issues/{number}/comments",
                               json={"body": message})
        resp = self.req_send(req, print_json=False)
        print(resp.json()["html_url"])

    def pr_edit(self, remote: Optional[str] = None, number: Optional[int] = None,
                title: Optional[str] = None, description: Optional[str] = None,
                append_description: Optional[str] = None,
                target_branch: Optional[str] = None, **kwargs: Any) -> None:
        """Change a pull request's title, description or target branch.

        append_description adds a paragraph after the current description.
        With no change given, opens the current description in an editor."""
        del kwargs
        repo = self.repo_path(remote)
        number = self.pr_number(repo, number)
        url = f"/repos/{repo}/pulls/{number}"
        data: Dict[str, Any] = {}
        if title:
            data["title"] = title
        if target_branch:
            data["base"] = target_branch
        if description is not None:
            data["body"] = description
        elif append_description:
            body = (self.get(url).get("body") or "").rstrip()
            data["body"] = f"{body}\n\n{append_description}" if body else append_description
        elif not data:
            data["body"] = interactive_edit(self.get(url).get("body") or "").strip()
        resp = self.req_send(requests.Request("PATCH", url, json=data), print_json=False)
        print(resp.json()["html_url"])

    def pr_close(self, remote: Optional[str] = None, number: Optional[int] = None,
                 message: Optional[str] = None, **kwargs: Any) -> None:
        """Close a pull request without merging it, first commenting message if given."""
        del kwargs
        repo = self.repo_path(remote)
        number = self.pr_number(repo, number)
        if message:
            self.req_send(requests.Request("POST", f"/repos/{repo}/issues/{number}/comments",
                                           json={"body": message}), print_json=False)
        resp = self.req_send(requests.Request("PATCH", f"/repos/{repo}/pulls/{number}",
                                              json={"state": "closed"}), print_json=False)
        print(resp.json()["html_url"])

SERVICES: Dict[str, Type[Service]] = {
    name: service
    for service in [Github, Bitbucket, Gitlab, Forgejo]
    for name in (service.name, service.alias)}

def main(argv: Optional[List[str]] = None, service: Optional[Type[Service]] = None) -> int:
    """Main function.

    With a service class, as for ggl, the service argument is implied and
    only the commands that service supports are offered."""
    argv = sys.argv[1:] if argv is None else argv

    def supports(func: str) -> bool:
        return service is None or hasattr(service, func)

    if service:
        parser = argparse.ArgumentParser(
            prog=f"g{service.alias}",
            description=f"A command-line interface to {service.display_name}.",
            fromfile_prefix_chars='@')
        parser.set_defaults(service=service.name)
    else:
        parser = argparse.ArgumentParser(description=__doc__, fromfile_prefix_chars='@')
        parser.add_argument("service", choices=list(SERVICES.keys()))
    # help = "one of {}".format(" ".join(SERVICES.keys())))
    parser.add_argument("-a", "--authinfo", help=".authinfo or .netrc file path",
                        default=os.path.expanduser("~/.authinfo"))
    parser.add_argument("-u", "--username", default=os.environ.get("GITHOST_USER") or None,
                        help="user name for the selected service (default: $GITHOST_USER, "
                        "else the first authinfo line for the host)")
    parser.add_argument("-b", "--base-url",
                        help="API base url, e.g. https://gitlab.example.com/api/v4 "
                        "for a self-hosted gitlab")
    parser.add_argument("-f", "--fingerprints",
                        help="display fingerprints of the selected service")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)


    subparsers = parser.add_subparsers(help="", dest="command", metavar="COMMAND")

    def add_command(name: str, deprecated: Tuple[str, ...] = (),
                    **kwargs: Any) -> argparse.ArgumentParser:
        """Adds a subcommand that also accepts its old names, kept out of the help.

        argparse has no hidden aliases, so the old names go straight into the
        name-to-parser map; the COMMAND metavar keeps them out of the usage line."""
        subparser = subparsers.add_parser(name, **kwargs)
        for old_name in deprecated:
            subparsers._name_parser_map[old_name] = subparser
        return subparser

    parser_postkey = add_command("add-key", deprecated=("key-post",),
                                 help="add an ssh public key")
    parser_postkey.add_argument("-p", "--pubkey-path",
                                default=os.path.expanduser("~/.ssh/id_rsa.pub"),
                                help="path to ssh public key file")
    parser_postkey.add_argument("-l", "--pubkey-label",
                                default=f"githost-{platform.node()}",
                                help="label for the public key")
    if service in (None, Bitbucket):
        parser_postkey.add_argument("-k", "--key-type", help="bitbucket key type")
    parser_postkey.set_defaults(func="post_key")

    parser_listrepos = add_command("ls-repo", deprecated=("repo-list",), aliases=["ls"],
                                   help="list available repositories")
    parser_listrepos.set_defaults(func="list_repos")

    parser_repocreate = add_command("create-repo", deprecated=("repo-create",),
                                    help="create a new repository")
    parser_repocreate.add_argument("-d", "--description", help="repo description")
    parser_repocreate.add_argument("-r", "--repo-name", default=os.path.basename(os.getcwd()),
                                   help="repository name")
    parser_repocreate.set_defaults(func="repo_create")

    remote_help = "git remote of the project (default: gitlab, else origin)"
    pr_remote_help = "git remote of the repo (default: forgejo, else origin)"

    if supports("collaborator_add"):
        parser_collabadd = subparsers.add_parser(
            "add-collaborator", help="add users to the current repo (forgejo)")
        parser_collabadd.add_argument("users", nargs="+", metavar="USER")
        parser_collabadd.add_argument("-R", "--remote", help=pr_remote_help)
        parser_collabadd.add_argument("-p", "--permission", default="write",
                                      choices=["read", "write", "admin"],
                                      help="default: write")
        parser_collabadd.set_defaults(func="collaborator_add")

    if supports("branch_protect"):
        parser_protect = subparsers.add_parser(
            "protect-branch", help="let only you push to or merge into a branch (forgejo)")
        parser_protect.add_argument("branch")
        parser_protect.add_argument("-R", "--remote", help=pr_remote_help)
        parser_protect.set_defaults(func="branch_protect")

    if supports("repo_publish"):
        parser_publish = subparsers.add_parser(
            "publish-repo", help="create the current repo, add collaborators, push a branch "
            "and let only you push to or merge into it (forgejo)")
        parser_publish.add_argument("-r", "--repo-name", default=os.path.basename(os.getcwd()),
                                    help="default: the current directory's name")
        parser_publish.add_argument("-d", "--description", help="repo description")
        parser_publish.add_argument("-c", "--collaborator", action="append",
                                    help="user to add with write access (repeatable)")
        parser_publish.add_argument("--branch", help="default: main, else master")
        parser_publish.set_defaults(func="repo_publish")

    if supports("mr_list"):
        parser_mrlist = subparsers.add_parser(
            "ls-mr", help="list your open and merged merge requests, and pushed branches "
            "without one, across all projects (gitlab)")
        parser_mrlist.set_defaults(func="mr_list")

    if supports("mr_create"):
        parser_mrcreate = subparsers.add_parser(
            "create-mr", help="open a merge request for a pushed branch (gitlab)")
        parser_mrcreate.add_argument("-R", "--remote", help=remote_help)
        parser_mrcreate.add_argument("-s", "--source-branch", help="default: current branch")
        parser_mrcreate.add_argument("-t", "--target-branch",
                                     help="default: project's default branch")
        parser_mrcreate.add_argument("--title", help="default: edit the last commit message")
        parser_mrcreate.add_argument("-d", "--description", help="merge request description")
        parser_mrcreate.set_defaults(func="mr_create")

    if supports("pr_list"):
        parser_prlist = subparsers.add_parser(
            "ls-pr", help="list the current repo's pull requests (forgejo)")
        parser_prlist.add_argument("-R", "--remote", help=pr_remote_help)
        parser_prlist.add_argument("-s", "--state", choices=["open", "closed", "all"],
                                   default="open")
        parser_prlist.set_defaults(func="pr_list")

    if supports("pr_create"):
        parser_prcreate = subparsers.add_parser(
            "create-pr", help="open a pull request for a pushed branch (forgejo)")
        parser_prcreate.add_argument("-R", "--remote", help=pr_remote_help)
        parser_prcreate.add_argument("-s", "--source-branch", help="default: current branch")
        parser_prcreate.add_argument("-t", "--target-branch",
                                     help="default: repo's default branch")
        parser_prcreate.add_argument("--title", help="default: edit the last commit message")
        parser_prcreate.add_argument("-d", "--description", help="pull request description")
        parser_prcreate.set_defaults(func="pr_create")

    if supports("pr_show"):
        parser_prshow = subparsers.add_parser(
            "show-pr", help="show a pull request with its comments and reviews (forgejo)")
        parser_prshow.add_argument("number", nargs="?", type=int,
                                   help="default: the open PR for the current branch")
        parser_prshow.add_argument("-R", "--remote", help=pr_remote_help)
        parser_prshow.set_defaults(func="pr_show")

    if supports("pr_comment"):
        parser_prcomment = subparsers.add_parser(
            "comment-pr", help="comment on a pull request (forgejo)")
        parser_prcomment.add_argument("number", nargs="?", type=int,
                                      help="default: the open PR for the current branch")
        parser_prcomment.add_argument("-R", "--remote", help=pr_remote_help)
        parser_prcomment.add_argument("-m", "--message", help="default: open an editor")
        parser_prcomment.add_argument("-r", "--reply-to", type=int, metavar="COMMENT_ID",
                                      help="quote this comment (an id from show-pr)")
        parser_prcomment.set_defaults(func="pr_comment")

    if supports("pr_edit"):
        parser_predit = subparsers.add_parser(
            "edit-pr", help="change a pull request's title, description or target (forgejo)")
        parser_predit.add_argument("number", nargs="?", type=int,
                                   help="default: the open PR for the current branch")
        parser_predit.add_argument("-R", "--remote", help=pr_remote_help)
        parser_predit.add_argument("--title", help="new title")
        group = parser_predit.add_mutually_exclusive_group()
        group.add_argument("-d", "--description", help="new description")
        group.add_argument("-a", "--append-description", metavar="TEXT",
                           help="add a paragraph after the current description")
        parser_predit.add_argument("-t", "--target-branch", help="new target branch")
        parser_predit.set_defaults(func="pr_edit")

    if supports("pr_close"):
        parser_prclose = subparsers.add_parser(
            "close-pr", help="close a pull request without merging it (forgejo)")
        parser_prclose.add_argument("number", nargs="?", type=int,
                                    help="default: the open PR for the current branch")
        parser_prclose.add_argument("-R", "--remote", help=pr_remote_help)
        parser_prclose.add_argument("-m", "--message", help="comment to post before closing")
        parser_prclose.set_defaults(func="pr_close")

    if supports("pr_wait"):
        parser_prwait = subparsers.add_parser(
            "wait-pr", help="wait for new feedback on a pull request (forgejo)")
        parser_prwait.add_argument("number", nargs="?", type=int,
                                   help="default: the open PR for the current branch")
        parser_prwait.add_argument("-R", "--remote", help=pr_remote_help)
        parser_prwait.add_argument("-i", "--interval", type=float, default=30,
                                   help="seconds between checks (default: 30)")
        parser_prwait.add_argument("-s", "--since", metavar="EVENT",
                                   help="only feedback after this comment:ID or review:ID, "
                                   "or none for any (default: your last comment or review)")
        parser_prwait.set_defaults(func="pr_wait")

    if not argv:
        parser.print_help(sys.stderr)
        return 0
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help(sys.stderr)
        return 0

    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    if args.verbose:
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    auth = Auth(user=args.username, authinfo=args.authinfo, passwd=None)
    service_cls = SERVICES.get(args.service)
    if not service_cls:
        raise ValueError(f"Invalid service: {args.service}")
    svc = service_cls(auth=auth)
    if args.base_url:
        svc.base = args.base_url.rstrip("/")
    fn = getattr(svc, args.func, None)
    if not fn:
        parser.error(f"{args.func} is not supported for {svc.name}")
    logger.debug(args)
    fn(**vars(args))
    return 0

def main_github() -> int:
    """Entry point for ggh: githost with the github service selected."""
    return main(service=Github)

def main_gitlab() -> int:
    """Entry point for ggl: githost with the gitlab service selected."""
    return main(service=Gitlab)

def main_forgejo() -> int:
    """Entry point for gfj: githost with the forgejo service selected."""
    return main(service=Forgejo)

def main_bitbucket() -> int:
    """Entry point for gbb: githost with the bitbucket service selected."""
    return main(service=Bitbucket)

if __name__ == "__main__":
    main()

# Local Variables:
# compile-command: "./githost.py -s bitbucket -v listrepos"
# End:
