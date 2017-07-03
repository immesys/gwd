import requests
import re
import hashlib
import urllib
import os
import binascii

class NoReachableEndpointException (Exception):
    pass

class InvalidNameException (Exception):
    pass

class NoWDTokenException (Exception):
    pass

class OperationFailedException(Exception):
    pass

def _load_wd_token():
    if "WD_TOKEN" in os.environ:
        return os.environ["WD_TOKEN"][:64]
    try:
        with open(".wd_token","rb") as f:
            return f.read()[:64]
    except IOError:
        pass
    try:
        with open(os.environ["HOME"]+"/.wd_token","rb") as f:
            return f.read()[:64]
    except IOError:
        pass
    try:
        with open("/etc/wd/token","rb") as f:
            return f.read()[:64]
    except IOError:
        pass
    raise NoWDTokenException("Could not find a WD token")

_wd_token = binascii.unhexlify(_load_wd_token())

def _do_request(urlsuffix):
    for endpoint in ["https://wd-a.steelcode.com/",
                     "https://wd-b.steelcodecom/",
                     "https://wd-c.steelcode.com/"]:
        try:
            r = requests.get(endpoint+urlsuffix)
            return r
        except requests.exceptions.RequestException:
            #that's fine, we'll try the next endpoint
            pass

    raise NoReachableEndpointException()

def _valid_prefix(prefix):
    if re.match("^[a-z0-9\\._]+$", prefix) is None:
        raise InvalidNameException("Watchdog names must match [a-z0-9\\._]+")

def make_body(token, name):
    return token + name.encode()

def kick(name, timeout=300):
    _valid_prefix(name)
    body = make_body(_wd_token, name)
    hmac=hashlib.sha256(body).hexdigest()
    r = _do_request("kick/%s?timeout=%d&hmac=%s" % (name, timeout, hmac))
    if r.status_code != 200:
        raise OperationFailedException(r.text)

def fault(name, reason="unspecified"):
    _valid_prefix(name)
    body = make_body(_wd_token, name)
    hmac=hashlib.sha256(body).hexdigest()
    r = _do_request("fault/%s?reason=%s&hmac=%s" % (name, urllib.quote(reason), hmac))
    if r.status_code != 200:
        raise OperationFailedException(r.text)

def retire(prefix):
    _valid_prefix(prefix)
    body = make_body(_wd_token, prefix)
    hmac=hashlib.sha256(body).hexdigest()
    r = _do_request("retire/%s?hmac=%s" % (prefix, hmac))
    if r.status_code != 200:
        raise OperationFailedException(r.text)

def status(prefix):
    _valid_prefix(prefix)
    body = make_body(_wd_token, prefix)
    hmac=hashlib.sha256(body).hexdigest()
    r = _do_request("status/%s?hmac=%s&header=0" % (prefix, hmac))
    if r.status_code != 200:
        raise OperationFailedException(r.text)
    rv = []
    for l in r.text.splitlines():
        parts = l.split("\t")
        rv.append({"state":parts[0], "name":parts[1],"expire":parts[2], "cumdtime":int(parts[3]), "reason":parts[4]})
    return rv

def auth(prefix):
    _valid_prefix(prefix)
    body = make_body(_wd_token, prefix)
    hmac=hashlib.sha256(body).hexdigest()
    r = _do_request("auth/%s?hmac=%s" % (prefix, hmac))
    if r.status_code != 200:
        raise OperationFailedException(r.text)
    return r.text
