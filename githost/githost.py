#!/usr/bin/python3

"""A command-line interface to git repository hosting services"""

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
import traceback
import urllib

from dataclasses import dataclass
import requests

logger = logging.getLogger(__name__)
logging.basicConfig()

try:
    __version__ = importlib.metadata.version('githost')
except Exception:
    __version__ = f"unknown: {traceback.format_exc()}"

def interactive_edit(initial_contents):
    """Open an editor to interactively edit a text template."""
    tmp = os.path.expanduser("~/.githost.tmp")
    editor = os.getenv("VISUAL") or os.getenv("EDITOR") or "vi"
    with open(tmp, "w") as stream:
        print(initial_contents, file=stream)

    subprocess.call([editor, tmp])

    with open(tmp, "r") as fh:
        contents = fh.read()
        return contents

def read_choice(choices, prompt="select: "):
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

def git(*args):
    """Run a git command and return its stripped output."""
    return subprocess.check_output(["git", *args], text=True).strip()

def parse_remote_url(url):
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

def x_www_browser(url):
    """Open the given url using the system's browser."""
    subprocess.run(["x-www-browser", url], check = True)

@dataclass
class Auth:
    """Authentication information."""
    user: str
    passwd: str
    authinfo: str


class Service:
    """Base class holding the common implementation for interacting with a git-hosting service."""
    name = None
    alias = None
    base = None
    def __init__(self, auth):
        self.auth = auth

    def read_authinfo(self):
        """Try looking up auth details from the user's authinfo file."""
        auth = self.auth
        authinfo = auth.authinfo
        if authinfo and os.path.exists(authinfo):
            machine = self.api_host()
            # TODO(ealfonso) support changing token order
            pat = re.compile("^machine {} login (.*) password (.*)"
                             .format(re.escape(machine)))
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

    def api_host(self):
        """Extract the git-hosting service hostname."""
        return urllib.parse.urlparse(self.base).hostname

    def write_authinfo(self, authinfo):
        """Persist the gathered credentials into the user's authinfo."""
        user, passwd=self.user(), self.password()
        assert authinfo
        machine = self.api_host()
        with open(authinfo, "a") as fh:
            print(f"machine {machine} login {user} password {passwd}", file = fh)

    def user(self, prompt="enter username: "):
        """Read or prompt for the service username."""
        if not self.auth.user and not self.read_authinfo():
            self.auth.user = input(prompt)
        return self.auth.user

    def password(self, prompt="enter password: "):
        """Read or prompt for the service password or token."""
        if not self.auth.passwd and not self.read_authinfo():
            self.auth.passwd = getpass.getpass(prompt)
            authinfo = self.auth.authinfo
            passwd = self.auth.passwd
            if read_choice(["yes", "no"],
                           prompt=f"write to {authinfo}? ") == "yes":
                self.write_authinfo(authinfo)
            self.auth.passwd = passwd
        return self.auth.passwd

    def req_auth(self, req, prompt=None):
        """Fill in the request's authentication details."""
        kwargs = {"prompt": prompt} if prompt else {}
        # uses basic auth by default
        req.auth = (self.user(), self.password(**kwargs))

    def req_send(self, req, add_auth=True, print_json=True, missing_ok=False):
        """Send the request after filling in auth details and parses the response.

        With missing_ok, a 404 returns None instead of raising."""
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
        else:
            if print_json:
                print (json.dumps(resp.json(), indent=4))
            return resp
        return None

    def git_add_remote(self, name, url):
        """Register the current githost service locally as a git remote."""
        cmd = ["git", "remote", "add", name, url]
        subprocess.run(cmd, check = True)

    def repo_name(self):
        """Returns the repository name."""
        cand = os.path.basename(os.getcwd())
        repo_name = input(f"repo name (default {cand}): ")
        return repo_name or cand

class Github(Service):
    """Manage the interaction with a Github repository host."""
    name = "github"
    alias = "gh"
    base = "https://api.github.com"

    TOKEN_URL = "https://github.com/settings/tokens"

    def __init__(self, auth):
        super().__init__(auth)
        self.fingerprints = """
        These are GitHub's public key fingerprints (in hexadecimal format):

16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48 (RSA)
ad:1c:08:a4:40:e3:6f:9c:f5:66:26:5d:4b:33:5d:8c (DSA)
These are the SHA256 hashes shown in OpenSSH 6.8 and newer (in base64 format):

SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8 (RSA)
SHA256:br9IjFspm1vxR3iA35FWE+4VTyz1hYVLIE2t1/CeyWQ (DSA)
        """

    def req_auth(self, req, prompt=None):
        super().req_auth(
            req,
            prompt=f"enter github token ({self.TOKEN_URL}): ")
        req.headers["User-Agent"] = "anon"
        req.headers["Authorization"] = f"token {self.auth.passwd}"

    # TODO(ealfonso) rename to key_post
    def post_key(self, pubkey_path, pubkey_label, **kwargs):
        """Post the given ssh public key to github."""
        del kwargs
        with open(pubkey_path, "r") as fh:
            pubkey = fh.read()
        data = {"key": pubkey, "title": pubkey_label}
        url = "/user/keys"
        req = requests.Request("POST", url, json=data)
        self.req_send(req)

    def repo_create(self, repo_name, description, private=True, **kwargs):
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
    def ensure_on_git_repo_directory():
        """Make sure we're on a git repo directory."""
        subprocess.check_output(["git", "status"])

    def list_repos(self, **kwargs):
        """List remote repositories."""
        del kwargs
        self.req_send(requests.Request("GET", "/user/repos"))


class Bitbucket(Service):
    """Manage the interaction with a Bitbucket repository host."""
    name = "bitbucket"
    alias = "bb"
    base = "https://api.bitbucket.org/2.0"
    # base = "http://localhost:1231"

    def post_key(self, pubkey_path, pubkey_label, key_type=None, repo_name=None, **kwargs):
        """Post the public ssh key to github."""
        del kwargs
        with open(pubkey_path, "r") as fh:
            pubkey = fh.read().strip()

        key_types = ("deploy", "ssh")
        key_type = key_type or read_choice(key_types)
        if not key_type in key_types:
            key_types = ",".join(key_types)
            raise Exception(f"Must specificy key type: {key_types}")

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

    def list_repos(self, **kwargs):
        """List the repos under the github account."""
        del kwargs
        url = f"/repositories/{self.user()}"
        req = requests.Request("GET", url)
        self.req_send(req)

    def repo_create(self, repo_name, description, private=True, **kwargs):
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
    alias = "gl"
    base = "https://gitlab.com/api/v4"

    def token_url(self):
        """Returns the url where a personal access token can be created."""
        return f"https://{self.api_host()}/-/user_settings/personal_access_tokens"

    def req_auth(self, req, prompt=None):
        super().req_auth(
            req,
            prompt=f"enter gitlab token with api scope ({self.token_url()}): ")
        # gitlab's API authenticates with a token header, not basic auth
        req.auth = None
        req.headers["PRIVATE-TOKEN"] = self.auth.passwd

    def post_key(self, pubkey_path, pubkey_label, **kwargs):
        """Post the given ssh public key to gitlab."""
        del kwargs
        with open(pubkey_path, "r") as fh:
            pubkey = fh.read().strip()
        data = {"key": pubkey, "title": pubkey_label}
        req = requests.Request("POST", "/user/keys", json=data)
        self.req_send(req)

    def list_repos(self, **kwargs):
        """List the projects owned by the gitlab user."""
        del kwargs
        req = requests.Request("GET", "/projects", params={"owned": "true"})
        self.req_send(req)

    def repo_create(self, repo_name, description, private=True, **kwargs):
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

    def project_id(self, remote=None):
        """Returns the url-encoded gitlab project path of the current repo.

        Defaults to the "gitlab" remote if it exists, otherwise "origin"."""
        if not remote:
            remote = "gitlab" if "gitlab" in git("remote").split() else "origin"
        host, path = parse_remote_url(git("remote", "get-url", remote))
        if host != self.api_host():
            sys.exit(f"remote {remote} is on {host}, not {self.api_host()}: "
                     "pick a gitlab remote with -R, or pass -b for a self-hosted gitlab")
        return urllib.parse.quote(path, safe="")

    def get_all(self, url, params=None):
        """GET every page of a gitlab list endpoint."""
        params = dict(params or {}, per_page=100)
        items = []
        page = "1"
        while page:
            params["page"] = page
            req = requests.Request("GET", url, params=dict(params))
            resp = self.req_send(req, print_json=False)
            items.extend(resp.json())
            page = resp.headers.get("X-Next-Page")
        return items

    def get(self, url, params=None):
        """GET a gitlab resource, or None if it does not exist."""
        req = requests.Request("GET", url, params=params)
        resp = self.req_send(req, print_json=False, missing_ok=True)
        return None if resp is None else resp.json()

    def mr_list(self, **kwargs):
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
        projects = {}
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

    def mr_create(self, remote=None, source_branch=None, target_branch=None,
                  title=None, description=None, **kwargs):
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

SERVICES = {name: service
            for service in [Github, Bitbucket, Gitlab]
            for name in (service.name, service.alias)}

def main(argv=None):
    """Main function."""
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(fromfile_prefix_chars='@')
    parser.add_argument("service", choices=list(SERVICES.keys()))
    # help = "one of {}".format(" ".join(SERVICES.keys())))
    parser.add_argument("-a", "--authinfo", help=".authinfo or .netrc file path",
                        default=os.path.expanduser("~/.authinfo"))
    parser.add_argument("-u", "--username", help="user name for the selected service")
    parser.add_argument("-b", "--base-url",
                        help="API base url, e.g. https://gitlab.example.com/api/v4 "
                        "for a self-hosted gitlab")
    parser.add_argument("-f", "--fingerprints",
                        help="display fingerprints of the selected service")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)


    subparsers = parser.add_subparsers(help="")

    parser_postkey = subparsers.add_parser("key-post", help="post an ssh key")
    parser_postkey.add_argument("-p", "--pubkey-path",
                                default=os.path.expanduser("~/.ssh/id_rsa.pub"),
                                help="path to ssh public key file")
    parser_postkey.add_argument("-l", "--pubkey-label",
                                default=f"githost-{platform.node()}",
                                help="label for the public key")
    parser_postkey.add_argument("-k", "--key-type", help="bitbucket key type")
    parser_postkey.set_defaults(func="post_key")

    parser_listrepos = subparsers.add_parser("repo-list", help="list available repositories")
    parser_listrepos.set_defaults(func="list_repos")

    parser_repocreate = subparsers.add_parser("repo-create", help="create a new repository")
    parser_repocreate.add_argument("-d", "--description", help="repo description")
    parser_repocreate.add_argument("-r", "--repo-name", default=os.path.basename(os.getcwd()),
                                   help="repository name")
    parser_repocreate.set_defaults(func="repo_create")

    remote_help = "git remote of the project (default: gitlab, else origin)"

    parser_mrlist = subparsers.add_parser(
        "ls-mr", help="list your open and merged merge requests, and pushed branches "
        "without one, across all projects (gitlab)")
    parser_mrlist.set_defaults(func="mr_list")

    parser_mrcreate = subparsers.add_parser(
        "create-mr", help="open a merge request for a pushed branch (gitlab)")
    parser_mrcreate.add_argument("-R", "--remote", help=remote_help)
    parser_mrcreate.add_argument("-s", "--source-branch", help="default: current branch")
    parser_mrcreate.add_argument("-t", "--target-branch", help="default: project's default branch")
    parser_mrcreate.add_argument("--title", help="default: edit the last commit message")
    parser_mrcreate.add_argument("-d", "--description", help="merge request description")
    parser_mrcreate.set_defaults(func="mr_create")

    if not argv:
        parser.print_help(sys.stderr)
        return 0
    args = parser.parse_args(argv)

    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    if args.verbose:
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    auth = Auth(user=args.username, authinfo=args.authinfo, passwd=None)
    service_fn = SERVICES.get(args.service)
    if not service_fn:
        raise ValueError(f"Invalid service: {args.service}")
    service = service_fn(auth=auth)
    if args.base_url:
        service.base = args.base_url.rstrip("/")
    fn = getattr(service, args.func, None)
    if not fn:
        parser.error(f"{args.func} is not supported for {service.name}")
    logger.debug(args)
    fn(**vars(args))
    return 0

def main_github():
    """Entry point for githost-gh: githost with the github service selected."""
    return main(["github", *sys.argv[1:]])

def main_gitlab():
    """Entry point for githost-gl: githost with the gitlab service selected."""
    return main(["gitlab", *sys.argv[1:]])

def main_bitbucket():
    """Entry point for githost-bb: githost with the bitbucket service selected."""
    return main(["bitbucket", *sys.argv[1:]])

if __name__ == "__main__":
    main()

# Local Variables:
# compile-command: "./githost.py -s bitbucket -v listrepos"
# End:
