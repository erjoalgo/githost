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

class Auth(object):
    def __init__(self, user=None, passwd=None, authinfo=None):
        self.user = user
        self.passwd = passwd
        # self._token = token
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

    def __init__(auth):
        # super(Github, self).__init__()
        self.auth = auth
        self.fingerprints = """
        These are GitHub's public key fingerprints (in hexadecimal format):

16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48 (RSA)
ad:1c:08:a4:40:e3:6f:9c:f5:66:26:5d:4b:33:5d:8c (DSA)
These are the SHA256 hashes shown in OpenSSH 6.8 and newer (in base64 format):

SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8 (RSA)
SHA256:br9IjFspm1vxR3iA35FWE+4VTyz1hYVLIE2t1/CeyWQ (DSA)
        """

    def post_key(self, pubkey_path, pubkey_label, **kwargs):
        assert user
        pubkey = open(pubkey_path).read()
        data = {"key": pubkey, "title": pubkey_label}
        url = "{}/user/keys".format(self.base)
        req = requests.Request("POST", url, json=data)
        self.req_send(req)


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
        user = self.user or read_user()
        url = "{}/repositories/{}/{}/deploy-keys".format(
            self.base, self.user(), repo_name)

        req = requests.Request("POST", url, json=data)
        # req.headers["Content-type"] = "application/json"
        # req.headers["Accept-Encoding"] = "identity"
        # del req.headers["Accept-Encoding"]
        # req.headers["Accept"] = "*/*"
        # req.headers["User-Agent"] = "curl/7.52.1"
        self.req_send(req)

    def list_repos(self, **kwargs):
        user = self.user or read_user()
        url = "{}/repositories/{}".format(self.base, self.user())
        req = requests.Request("GET", url)
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
    parser_postkey.add_argument("-r", "--repo-name", default=os.path.basename(os.getcwd()),
                                help = "repository name")
    parser_postkey.set_defaults(func="post_key")

    parser_listrepos = subparsers.add_parser("listrepos", help="list available repositories")
    parser_listrepos.set_defaults(func="list_repos")

    args=parser.parse_args()

    if args.verbose:
        print ("debug on...")
        logger.setLevel(logging.DEBUG)
        # requests_log = logging.getLogger("requests.packages.urllib3")
        # requests_log.setLevel(logging.DEBUG)
        # requests_log.propagate = True
        # httplib.HTTPConnection.debuglevel = 2


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
