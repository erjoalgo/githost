#!/usr/bin/python3

"""A command-line interface to git repository hosting services"""

from __future__ import absolute_import
from __future__ import print_function

from six.moves import input
from six.moves.urllib.parse import urlparse
import argparse
import getpass
import importlib.metadata
import json
import logging
import os
import platform
import re
import requests
import subprocess
import sys
import traceback

logger = logging.getLogger(__name__)
logging.basicConfig()

try:
    __version__ = importlib.metadata.version('githost')
except:
    __version__ = f"unknown: {traceback.format_exc()}"

def interactive_edit(initial_contents):
    """Open an editor to interactively edit a text template."""
    tmp = os.path.expanduser("~/.githost.tmp")
    editor = os.getenv("VISUAL") or os.getenv("EDITOR") or "vi"
    with open(tmp, "w") as stream:
        print(initial_contents, file=stream)

    subprocess.call([editor, tmp])

    contents = open(tmp, "r").read()
    return contents

def read_choice(choices, prompt="select: "):
    """Prompt user for the index of their selection."""
    while True:
        print ("\n".join("{}: {}".format(i, choice)
                         for (i, choice) in enumerate(choices)))
        resp = input(prompt)
        try:
            idx = int(resp)
            return choices[idx]
        except:
            pass

def call(cmd):
    ret = subprocess.call(cmd)
    if ret != 0:
        raise Exception("non-zero exit: {}".format(" ".join(cmd)))

def x_www_browser(url):
    try:
        call(["x-www-browser", url])
    except Exception as ex:
        logging.error("failed to open x browser: ", ex)

class Auth(object):
    def __init__(self, user=None, passwd=None, authinfo=None):
        self.user = user
        self.passwd = passwd
        self.authinfo = authinfo


class Service(object):
    name = None
    base = None
    def __init__(self, auth):
        self.auth = auth

    def read_authinfo(self):
        auth = self.auth
        authinfo = auth.authinfo
        if authinfo and os.path.exists(authinfo):
            machine = self.api_host()
            # TODO(ealfonso) support changing token order
            pat = re.compile("^machine {} login (.*) password (.*)"
                             .format(re.escape(machine)))
            try:
                lines = open(authinfo).read().split("\n")
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

    def api_host(self):
        return urlparse(self.base).netloc

    def write_authinfo(self, authinfo):
        user, passwd=self.user(), self.password()
        assert authinfo
        machine = self.api_host()
        with open(authinfo, "a") as fh:
            print("machine {} login {} password {}"
                  .format(machine, user, passwd),
                  file = fh)

    def user(self, prompt="enter username: "):
        if not self.auth.user and not self.read_authinfo():
            self.auth.user = input(prompt)
        return self.auth.user

    def password(self, prompt="enter password: "):
        if not self.auth.passwd and not self.read_authinfo():
            self.auth.passwd = getpass.getpass(prompt)
            authinfo = self.auth.authinfo
            passwd = self.auth.passwd
            if read_choice(["yes", "no"],
                           prompt="write to {}? ".format(authinfo)):
              self.write_authinfo(authinfo)
            self.auth.passwd = passwd
        return self.auth.passwd

    def req_auth(self, req, prompt=None):
        kwargs = {"prompt": prompt} if prompt else {}
        req.auth = (self.user(), self.password(**kwargs))

    def req_send(self, req, add_auth=True):
        if not urlparse(req.url).netloc:
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

    def git_add_remote(self, name, url):
        cmd = ["git", "remote", "add", name, url]
        call(cmd)

    def repo_name(self):
        cand = os.path.basename(os.getcwd())
        repo_name = input("repo name (default {}): ".format(cand))
        return repo_name or cand

class Github(Service):
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
        x_www_browser(self.TOKEN_URL)
        super(Github, self).req_auth(
            req,
            prompt=f"enter github token ({self.TOKEN_URL}): ")
        req.headers["User-Agent"] = "anon"
        req.headers["Authorization"] = f"token {self.auth.passwd}"

    # TODO(ealfonso) rename to key_post
    def post_key(self, pubkey_path, pubkey_label, **kwargs):
        del kwargs
        pubkey = open(pubkey_path).read()
        data = {"key": pubkey, "title": pubkey_label}
        url = "/user/keys"
        req = requests.Request("POST", url, json=data)
        self.req_send(req)

    def repo_create(self, repo_name, description, private=True, **kwargs):
        del kwargs
        self.ensure_on_git_repo_directory()
        repo_name = self.repo_name()
        if not description:
            description = interactive_edit("# enter {} description".format(repo_name)).strip()

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
        clone_url = "ssh://git@github.com/{}/{}".format(self.user(), repo_name)
        self.git_add_remote("github", clone_url)

    @staticmethod
    def ensure_on_git_repo_directory():
        subprocess.check_output(["git", "status"])

    def list_repos(self, **kwargs):
        del kwargs
        self.req_send(requests.Request("GET", "/user/repos"))


class Bitbucket(Service):
    name = "bitbucket"
    base = "https://api.bitbucket.org/2.0"
    # base = "http://localhost:1231"

    def __init__(self, auth):
        super(Bitbucket, self).__init__(auth)

    def post_key(self, pubkey_path, pubkey_label, key_type=None, repo_name=None, **kwargs):
        del kwargs
        pubkey = open(pubkey_path).read().strip()

        key_types = ("deploy", "ssh")
        key_type = key_type or read_choice(key_types)
        if not key_type in key_types:
            raise Exception("Must specificy key type: {{}}".format(",".join(key_types)))

        data = {"key": pubkey, "label": pubkey_label}
        if key_type == "deploy":
            repo_name = self.repo_name()
            # if not repo_name:
                # raise Exception("Must specify repo name for deploy key post")
            url = "/repositories/{}/{}/deploy-keys".format(self.user(), repo_name)
        elif key_type == "ssh":
            url = "/users/{}/ssh-keys".format(self.user())

        req = requests.Request("POST", url, json=data)
        self.req_send(req)

    def list_repos(self, **kwargs):
        del kwargs
        url = "/repositories/{}".format(self.user())
        req = requests.Request("GET", url)
        self.req_send(req)

    def repo_create(self, repo_name, description, private=True, **kwargs):
        del kwargs
        repo_name = self.repo_name()
        if not description:
            description = interactive_edit("# enter {} description".format(repo_name)).strip()

        data = {
            # "project": {"key": repo_name},
            "description": description,
            "scm": "git",
            "private": private}
        url = "/repositories/{}/{}".format(self.user(), repo_name)
        req = requests.Request("POST", url, json=data)
        resp = self.req_send(req)
        # TODO(ejalfonso) get url from resp
        clone_url = "ssh://git@bitbucket.com/{}/{}".format(self.user(), repo_name)
        self.git_add_remote("bitbucket", clone_url)

SERVICES = dict((service.name, service)
                for service  in
                [Github, Bitbucket])

def main():
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
                                default="githost-{}".format(platform.node()),
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

    auth = Auth(user=args.username, authinfo=args.authinfo)
    service_fn = SERVICES.get(args.service)
    if not service_fn:
        raise ValueError(f"Invalid service: {args.service}")
    service = service_fn(auth=auth)
    fn = getattr(service, args.func)
    logger.debug(args)
    fn(**vars(args))

if __name__ == "__main__":
    main()

# Local Variables:
# compile-command: "./githost.py -s bitbucket -v listrepos"
# End:
