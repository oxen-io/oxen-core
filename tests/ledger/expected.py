import re
import time
from concurrent.futures import ThreadPoolExecutor
from vprint import vprint


executor = ThreadPoolExecutor(max_workers=1)


class MatchScreen:
    """
    Provides a call operator that matches each device line against a regex for the line.  Can
    optionally invoke callback when all the regexes match, e.g. to perform additional checks or
    extract data.  Note that regexes use .search, so should be anchored with ^ as needed.

    If allow_extra is given and True then the `ledger.curr()` is permitted to return results longer
    than the regex list; only the first `len(regexes)` elements are tested.

    If fail_index is given it should be an index >= 1 from which mismatches should be considered
    fatal: if the items before `fail_index` match the screen, then the ones from `fail_index`
    onwards *must* match or else we fatally fail with an exception.  This can be used, for example,
    to match something like `['Confirm Amount', '123']`: using fail_index=1 we would immediately
    fail (with exception) the test if we see `Confirm Amount` on the screen with any other value.
    (Without fail_index, we would keep re-testing the screen in such a case).

    If callback is specified and has a return value then it is cast that to bool and return it.  If
    not specified, has no return, or returns None then True is returned after calling the callback.

    callback, if given, will be invoked as `callback(curr_text, match_objects)` and can:
    - return a truthy value, None, or no return value to pass the interaction/match and proceed to
      the next interaction
    - return a falsey value (other than None) to fail the match and repeat the interaction
    - throw an exception to fail the test
    """

    def __init__(self, regexes, callback=None, *, allow_extra=False, fail_index=None):
        self.regexes = [re.compile(r) for r in regexes]
        self.callback = callback
        self.allow_extra = allow_extra
        self.fail_index = fail_index or len(self.regexes)
        self.desc = f"screen match: {regexes}"

    def __call__(self, ledger, *, immediate=False):
        text = ledger.curr()
        extra = len(text) - len(self.regexes)
        if extra >= 0 if self.allow_extra else extra == 0:
            matches = []
            for i in range(len(self.regexes)):
                matches.append(self.regexes[i].search(text[i]))
                if not matches[-1]:
                    if i >= self.fail_index or immediate:
                        vprint(f"fatal match fail: {text} against {self.desc}")
                        raise ValueError(f"wrong screen value: {text}, expected {self.desc}")
                    return False
            if self.callback:
                res = self.callback(text, matches)
                if res is not None:
                    res = bool(res)
                    if immediate and not res:
                        raise ValueError(f"wrong screen value: {text}, expected {self.desc}")
                    return res
            return True
        if immediate:
            raise ValueError(f"Wrong screen value: {text}")
        return False


class ExactScreen(MatchScreen):
    """
    Convenience wrapper around MatchScreen that
    Provides a call operator that returns True if we get an exact match on the ledger device, False
    otherwise.  `result` should be a list of strings (to match the result of ledger.curr()).

    Other arguments are forwarded to MatchScreen.
    """

    def __init__(self, result, *args, **kwargs):
        super().__init__(["^" + re.escape(x) + "$" for x in result], *args, **kwargs)


class MatchMulti:
    """
    Matches a multi-valued value on the screen, expected to be displayed as `{title} 1/N` through
    `{title} N/N` subscreens; once we match the first screen, we page through the rest,
    concatenating the values.  The final, concatenated value must match `value` (unless `value` is
    None).

    callback, if given, is invoked with the final, concatenated value.  (This can be used, for
    instance, with value=None to allow capturing the value).  Unlike MatchScreen, the callback's
    return value is ignored, but the callback can still throw or assert to cause a test failure.
    """

    def __init__(self, title, value, callback=None):
        self.title = title
        self.expected = value
        self.re = re.compile("^" + re.escape(title) + r" \(1/(\d+)\)$")
        self.callback = callback
        self.desc = f"multi-value {title}"

    def __call__(self, ledger, immediate=False):
        text = ledger.curr()
        if len(text) != 2:
            return False
        m = self.re.search(text[0])
        if not m:
            return False
        val = ledger.read_multi_value(self.title)
        if self.expected is not None and val != self.expected:
            raise ValueError(f"{self.title} value {val} did not match expected {self.expected}")

        if self.callback:
            self.callback(val)

        return True


class Do:
    """Fake matcher that just does some side effect (passing the ledger) and always returns True"""

    def __init__(self, action, desc=None):
        self.action = action
        if desc:
            self.desc = desc

    def __call__(self, ledger, immediate=False):
        self.action(ledger)
        return True


# Static Do objects that do a right/left/both push when invoked
Do.right = Do(lambda ledger: ledger.right(), desc="push right")
Do.left = Do(lambda ledger: ledger.left(), desc="push left")
Do.both = Do(lambda ledger: ledger.both(), desc="push both")


def run_with_interactions(ledger, main, *interactions, timeout=30, poll=0.25):
    """
    Uses a thread to call `main` and the given interactions in parallel.

    Each interaction is a callable that is passed the ledger instance and returns True if it
    succeeded, False if it did not match.  Upon a True return we move on to the next interaction and
    call it repeatedly (with delay `poll`) until it returns True, etc.

    If the timeout is reached, or the `main` command finishes, before all interactions pass then we
    raise an exception.

    In either case, we wait for `main` to finish and (if interactions passed) return its result or
    exception; otherwise we raise an error for the interactions timeout.
    """

    future = executor.submit(main)

    timeout_at = time.time() + timeout

    int_fail = None
    try:
        for f in interactions:
            while time.time() < timeout_at and not future.done():
                if f(ledger):
                    vprint(f"Interaction success: {f.desc if hasattr(f, 'desc') else f}")
                    break
                time.sleep(poll)
            else:
                desc = getattr(f, "desc", "device interaction")
                if time.time() < timeout_at:
                    raise EOFError(f"command finished before {desc} completed")
                else:
                    raise TimeoutError(f"timeout waiting for {desc}")
    except Exception as e:
        int_fail = e

    if int_fail is not None:
        try:
            future.result()
        except Exception as e:
            # Both raised, so throw containing both messages:
            raise RuntimeError(
                "Failed to run with interactions:\n"
                f"Run failure: {e}\n"
                f"Interactions failure: {int_fail}"
            )
        raise int_fail

    return future.result()


def check_interactions(ledger, *interactions):
    """Sort of like run_with_interactions except without a separate task to run, and without
    polling/timeouts: this expects all the given interacts to run and match immediately."""

    for f in interactions:
        f(ledger, immediate=True)
