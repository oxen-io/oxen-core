import requests
import urllib.parse
import time
import re


class SingleBaseSession(requests.Session):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url

    def request(self, method, url, *args, **kwargs):
        return super().request(method, urllib.parse.urljoin(self.base_url, url), *args, **kwargs)


class LedgerAPI:
    def __init__(self, api_url):
        self.api = SingleBaseSession(api_url)
        self._detect_buggy_crap()

    def curr(self):
        """Returns the text of events on the current screen"""
        return [e["text"] for e in self.api.get("/events?currentscreenonly=true").json()["events"]]

    def _touch(self, which, count, action, delay, sleep):
        json = {"action": action}
        if delay:
            json["delay"] = delay
        for _ in range(count):
            self.api.post(f"/button/{which}", json=json)
            if sleep:
                time.sleep(sleep)

    def left(self, count=1, *, sleep=0, action="press-and-release", delay=None):
        """
        Hit the left button `count` times; sleeps for `sleep` seconds after each push to wait for it
        to register.
        """
        self._touch("left", count, action, delay, sleep)

    def right(self, count=1, *, sleep=0, action="press-and-release", delay=None):
        """
        Hit the right button `count` times; sleeps for `sleep` seconds after each push to wait for
        it to register.
        """
        self._touch("right", count, action, delay, sleep)

    def both(self, *, sleep=0, action="press-and-release", delay=None):
        """
        Hit both buttons simultaneously; sleeps for `sleep` seconds after pushing to wait for it to
        register.
        """
        self._touch("both", 1, action, delay, sleep)

    def read_multi_value(self, title):
        """Feed this the ledger on the first "{title} (1/N)" screen and it will read through,
        collect the multi-part value, and return it.  Throws ValueError if there aren't screens 1/N
        through N/N.  Leaves the ledger on the final (N/N) screen."""

        text = self.curr()
        disp_n = re.search("^" + re.escape(title) + r" \(1/(\d+)\)$", text[0])
        if not disp_n:
            raise ValueError(f"Did not match a multi-screen {title} value: {text}")
        disp_n = int(disp_n[1])
        full_value = "".join(text[1:])
        i = 1
        while i < disp_n:
            self.right()
            i += 1
            text = self.curr()
            expected = f"{title} ({i}/{disp_n})"
            if text[0] != expected:
                raise ValueError(
                    f"Unexpected multi-screen value: expected {expected}, got {text[0]}"
                )
            full_value += "".join(text[1:])

        return full_value

    def _detect_buggy_crap(self):
        """Detects buggy speculos inability to detect capital S's on the Nano X screen.  This should
        be called when the device is on the main screen."""
        assert self.curr()[0] == "OXEN wallet"
        self.right()
        self.both()
        self.right(4)
        buggy_s_re = re.compile("^(S?)elect Network$")
        for t in self.curr():
            m = buggy_s_re.search(t)
            if m:
                self.buggy_S = len(m[1]) == 0
                self.right(3)
                self.both()
                break
        else:
            raise RuntimeError(
                "Did not find S?elect Network; perhaps the device was not on the main screen?"
            )

    def buggy_crap(self, x):
        if not self.buggy_S:
            return x
        if any(isinstance(x, t) for t in (int, float)):
            return x
        if isinstance(x, str):
            return x.replace("S", "")
        if isinstance(x, list):
            return [self.buggy_crap(i) for i in x]
        if isinstance(x, tuple):
            return tuple(self.buggy_crap(i) for i in x)
        if isinstance(x, dict):
            return {self.buggy_crap(k): self.buggy_crap(v) for k, v in x.items()}
        raise ValueError(f"Don't know how to bug-accomodate {type(x)}")
