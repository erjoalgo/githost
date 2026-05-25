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
                           prompt=f"write to {authinfo}? "):
              self.write_authinfo(authinfo)
            self.auth.passwd = passwd
        return self.auth.passwd

    def req_auth(self, req, prompt=None):
        """Fill in the request's authentication details."""
        kwargs = {"prompt": prompt} if prompt else {}
        req.auth = (self.user(), self.password(**kwargs))

    def req_send(self, req, add_auth=True):
        """Send the request after filling in auth details and parses the response."""
        if not urllib.parse.urlparse(req.url).hostname:
            req.url = self.base + req.url
        if add_auth:
            self.req_auth(req)
        logger.debug("%s %s:\n%s\n%s\n%s", req.method, req.url, req.json, req.data, req.params)
        resp = requests.Session().send(req.prepare())
        if not resp.ok:
            print (resp.text)
            resp.raise_for_status()
        else:
            data = json.loads(resp.text)
            print (json.dumps(data, indent=4))
            return resp
        return None

    def git_add_remote(self, name, url):
        """Register the current githost service locally as a git remote."""
        cmd = ["git", "remote", "add", name, url]
        call(cmd)

    def repo_name(self):
        """Returns the repository name."""
        cand = os.path.basename(os.getcwd())
        repo_name = input(f"repo name (default {cand}): ")
        return repo_name or cand

class Github(Service):
    """Manage the interaction with a Github repository host."""
    name = "github"
    base = "https://api.github.com"

    def __init__(self, auth):
        super(Github, self).__init__(auth)
        self.fingerprints = """
        These are GitHub's public key fingerprints (in hexadecimal format):

16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48 (RSA)
ad:1c:08:a4:40:e3:6f:9c:f5:66:26:5d:4b:33:5d:8c (DSA)
These are the SHA256 hashes shown in OpenSSH 6.8 and newer (in base64 format):

SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8 (RSA)
SHA256:br9IjFspm1vxR3iA35FWE+4VTyz1hYVLIE2t1/CeyWQ (DSA)
        """
        self.TOKEN_URL = "https://github.com/settings/tokens"

    def req_auth(self, req):
        super(Github, self).req_auth(
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
    base = "https://api.bitbucket.org/2.0"
    # base = "http://localhost:1231"

    def __init__(self, auth):
        super(Bitbucket, self).__init__(auth)

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
        # TODO(ejalfonso) get url from resp
        clone_url = f"ssh://git@bitbucket.com/{self.user()}/{repo_name}"
        self.git_add_remote("bitbucket", clone_url)

SERVICES = dict((service.name, service)
                for service  in
                [Github, Bitbucket])

def main():
    """Main function."""
    parser = argparse.ArgumentParser(fromfile_prefix_chars='@')
    parser.add_argument("service", choices=list(SERVICES.keys()))
    # help = "one of {}".format(" ".join(SERVICES.keys())))
    parser.add_argument("-a", "--authinfo", help=".authinfo or .netrc file path",
                        default=os.path.expanduser("~/.authinfo"))
    parser.add_argument("-u", "--username", help="user name for the selected service")
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

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return 0
    args = parser.parse_args()

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
    fn = getattr(service, args.func)
    logger.debug(args)
    fn(**vars(args))
    return 0

if __name__ == "__main__":
    main()

# Local Variables:
# compile-command: "./githost.py -s bitbucket -v listrepos"
# End:
