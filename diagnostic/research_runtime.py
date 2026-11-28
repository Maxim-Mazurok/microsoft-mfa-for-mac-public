"""Private storage and existing-identity loading for later bounded experiments.

No network or approval operations. Original P01/P02 executed sources are frozen.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import uuid

import p01
import p02_prepare
import push_protocol as p

require = p01.require
json_bytes = p01.json_bytes


def private_json(path):
    obj = json.loads(p02_prepare.private_config(path), object_pairs_hook=p._object)
    require(isinstance(obj, dict), "invalid_private_json")
    return obj


def private_directory(path):
    """Open an existing owned private directory without following any symlink."""
    require(path.is_absolute() and ".." not in path.parts, "absolute_private_path_required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022,
                    "insecure_private_ancestor")
        info = os.fstat(fd)
        require(info.st_uid == os.getuid() and not info.st_mode & 0o077, "insecure_private_directory")
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)


def load_p01(root):
    push = root / ".secrets/push"
    lock = private_json(push / "p01-attempt.lock")
    require(isinstance(lock.get("run_id"), str) and re.fullmatch(r"[0-9a-f]{32}", lock["run_id"]),
            "invalid_p01_locator")
    prior = push / lock["run_id"]
    report = private_json(prior / "report.json")
    require(report.get("experiment") == "P01" and report.get("run_id") == lock["run_id"]
            and report.get("fresh_credentials_observed") is True
            and report.get("mcs_accepted") is True and report.get("checkin_posts_attempted") == 1,
            "successful_p01_provenance_required")
    data = private_json(prior / "credentials.json")
    require(set(data) == {"android_id", "security_token"}
            and all(isinstance(v, str) and re.fullmatch(r"[1-9][0-9]{0,19}", v) for v in data.values()),
            "invalid_p01_credentials")
    credentials = p.CheckinCredentials(int(data["android_id"]), int(data["security_token"]))
    credentials.validate()
    return credentials


class PrivateRun:
    def __init__(self, root, experiment, filenames):
        require(bool(re.fullmatch(r"[a-z][0-9]{2}", experiment)), "invalid_experiment_identifier")
        require(all(re.fullmatch(r"[a-z0-9-]+\.(?:json|bin|txt)", name) for name in filenames),
                "invalid_private_filename")
        self.fd, self.run_id, self.filenames = None, uuid.uuid4().hex, frozenset(filenames)
        parent = private_directory(root / ".secrets/push")
        try:
            try:
                fd = os.open(experiment + "-attempt.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
            except FileExistsError:
                raise p01.ProbeError("experiment_attempt_already_reserved_no_retry") from None
            with os.fdopen(fd, "wb") as stream:
                stream.write(json_bytes({"experiment": experiment, "run_id": self.run_id,
                                         "automatic_retry_permitted": False}))
                stream.flush(); os.fsync(stream.fileno())
            os.fsync(parent)
            os.mkdir(self.run_id, 0o700, dir_fd=parent)
            self.fd = os.open(self.run_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        finally:
            os.close(parent)

    @contextmanager
    def capture(self, name):
        require(name in self.filenames, "invalid_private_filename")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        with os.fdopen(fd, "wb") as stream:
            try:
                yield stream
            finally:
                stream.flush(); os.fsync(stream.fileno())

    write = p01.PrivateRun.write
    close = p01.PrivateRun.close
