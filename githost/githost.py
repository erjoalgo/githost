#!/usr/bin/python

"""A command-line interface to git repository hosting services"""

from __future__ import print_function

import argparse
import platform
import os
import logging
import getpass
import re
import json
import traceback
from urlparse import urlparse

import requests
from requests import Request, Session
import httplib
import subprocess
import traceback


logger = logging.getLogger(__name__)

try:
    from ._version import __version__
except:
    traceback.print_exc()
    __version__ = "unknown"

def interactive_edit(initial_contents):
    tmp = os.path.expanduser("~/.githost.tmp")
    editor = os.getenv("VISUAL") or os.getenv("EDITOR") or "vi"
    with open(tmp, "w") as fh:
        print(initial_contents, file=fh)

    subprocess.call([editor, tmp])

    contents = open(tmp, "r").read()
    return contents

def read_choice(choices, prompt="select: "):
    while True:
        print ("\n".join("{}: {}".format(i, choice)
                         for (i, choice) in enumerate(choices)))
        resp = input(prompt)
        try:
            idx = int(resp)
            return choices[idx]
        except:
            pass

class Auth(object):
    def __init__(self, user=None, passwd=None, authinfo=None):
        self.user = user
        self.passwd = passwd
        self.authinfo = authinfo


class Service(object):
    def __init__(self, auth):
        self.auth = auth

    def read_authinfo(self):
        auth = self.auth
        authinfo = auth.authinfo
        if authinfo and os.path.exists(authinfo):
            parsed = urlparse(self.base)
            # TODO(ealfonso) support changing token order
            pat = re.compile("^machine {} login (.*) password (.*)"
                             .format(re.escape(parsed.netloc)))
            with open(authinfo, "r") as fh:
                for line in fh:
                    m = pat.match(line)
                    if m:
                        auth.user = m.group(1)
                        auth.passwd = m.group(2)
                        return auth

    def user(self, prompt="enter username: "):
        if not self.auth.user and not self.read_authinfo():
            self.auth.user = raw_input(prompt)
        return self.auth.user

    def password(self, prompt="enter password: "):
        if not self.auth.passwd and not self.read_authinfo():
            self.auth.passwd = getpass.getpass(prompt)
        return self.auth.passwd

    def req_auth(self, req):
        req.auth = (self.user(), self.password())

    def req_send(self, req, add_auth=True):
        # TODO(ealfonso) only enhance if missing host
        req.url = self.base + req.url
        if add_auth:
            self.req_auth(req)
        resp = requests.Session().send(req.prepare())
        if not resp.ok:
            print (resp.text)
            resp.raise_for_status()
        else:
            data = json.loads(resp.text)
            print (json.dumps(data, indent=4))
            return resp

class Github(Service):
    name = "github"
    base = "https://api.github.com"

    def __init__(self, auth):
        self.auth = auth
        self.fingerprints = """
        These are GitHub's public key fingerprints (in hexadecimal format):

16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48 (RSA)
ad:1c:08:a4:40:e3:6f:9c:f5:66:26:5d:4b:33:5d:8c (DSA)
These are the SHA256 hashes shown in OpenSSH 6.8 and newer (in base64 format):

SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8 (RSA)
SHA256:br9IjFspm1vxR3iA35FWE+4VTyz1hYVLIE2t1/CeyWQ (DSA)
        """

    def req_auth(self, req):
        super(Github, self).req_auth(req)
        req.headers["User-Agent"]="anon"

    # TODO(ealfonso) rename to key_post
    def post_key(self, pubkey_path, pubkey_label, **kwargs):
        pubkey = open(pubkey_path).read()
        data = {"key": pubkey, "title": pubkey_label}
        url = "/user/keys"
        req = requests.Request("POST", url, json=data)
        self.req_send(req)

    def repo_create(self, repo_name, description, private=True, **kwargs):
        assert repo_name
        if not description:
            description = interactive_edit("# enter {} description".format(repo_name)).strip()

        data = {"name": repo_name,
                "description": description,
                "private": private,
                "has_issues": True,
                "has_projects": True,
                "has_wiki": True}
        url = "/user/repos"
        req = Request("POST", url, json=data)
        self.req_send(req)

    def list_repos(self, **kwargs):
        self.req_send(Request("GET", "/user/repos"))


class Bitbucket(Service):
    name = "bitbucket"
    base = "https://api.bitbucket.org/2.0"
    # base = "http://localhost:1231"

    def __init__(self, auth):
        self.auth = auth

    def post_key(self, pubkey_path, pubkey_label, repo_name, **kwargs):
        assert repo_name
        pubkey = open(pubkey_path).read()
        data = {"key": pubkey.strip(), "label": pubkey_label}
        user = self.user()
        url = "/repositories/{}/{}/deploy-keys".format(self.user(), repo_name)
        req = requests.Request("POST", url, json=data)
        self.req_send(req)

    def list_repos(self, **kwargs):
        user = self.user()
        url = "/repositories/{}".format(self.user())
        req = requests.Request("GET", url)
        self.req_send(req)

    def repo_create(self, repo_name, description, private=True, **kwargs):
        assert repo_name
        if not description:
            description = interactive_edit("# enter {} description".format(repo_name)).strip()

        data = {
            # "project": {"key": repo_name},
            "description": description,
            "scm": "git",
            "private": private}
        url = "/repositories/{}/{}".format(self.user(), repo_name)
        req = Request("POST", url, json=data)
        self.req_send(req)

SERVICES = {Github.name: Github,
            Bitbucket.name: Bitbucket}

def main():
    parser = argparse.ArgumentParser(fromfile_prefix_chars='@')
    parser.add_argument("-s", "--service", choices=SERVICES.keys())
    # help = "one of {}".format(" ".join(SERVICES.keys())))
    parser.add_argument("-a", "--authinfo", help = ".authinfo or .netrc file path",
                        default=os.path.expanduser("~/.authinfo"))
    parser.add_argument("-u", "--username", help = "user name for the selected service")
    parser.add_argument("-f", "--fingerprints",
                        help = "display fingerprints of the selected service")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)


    subparsers = parser.add_subparsers(help="")

    parser_postkey = subparsers.add_parser("postkey", help="post an ssh key")
    parser_postkey.add_argument("-p", "--pubkey-path",
                                default=os.path.expanduser("~/.ssh/id_rsa.pub"),
                                help = "path to ssh public key file")
    parser_postkey.add_argument("-l", "--pubkey-label",
                                default="githost-{}".format(platform.node()),
                                help = "label for the public key")
    parser_postkey.add_argument("-r", "--repo-name", help = "repository name")
    parser_postkey.set_defaults(func="post_key")

    parser_listrepos = subparsers.add_parser("listrepos", help="list available repositories")
    parser_listrepos.set_defaults(func="list_repos")

    parser_repocreate = subparsers.add_parser("repocreate", help="create a new repository")
    parser_repocreate.add_argument("-d", "--description", help = "repo description")
    parser_repocreate.add_argument("-r", "--repo-name", default=os.path.basename(os.getcwd()),
                                   help = "repository name")
    parser_repocreate.set_defaults(func="repo_create")

    args=parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    auth = Auth(user=args.username, authinfo=args.authinfo)
    service = SERVICES[args.service](auth=auth)
    fn = getattr(service, args.func)
    print (args)
    fn(**vars(args))

if __name__ == "__main__":
    main()

# Local Variables:
# compile-command: "./githost.py -s bitbucket -v listrepos"
# End:
