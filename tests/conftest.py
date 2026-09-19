"""The suite is offline. This makes that structural rather than aspirational.

`pyproject.toml` has declared a ``network`` marker and the docs have promised
an offline suite since the beginning, but nothing enforced either. A test that
reached the internet simply worked - slowly, and only while somebody else's
server was up. One did: a phone-card test spent **ninety-five seconds** of a
hundred-and-five-second run waiting on live lookups, and it was invisible
because the suite still passed.

So every test runs with the socket closed. :meth:`Fetcher._once` is the single
place in the project that opens one, and here it returns a transport failure
instead - the same shape a real unreachable host produces, which means the
code under test takes its ordinary "source unavailable" path rather than a
special one that only exists during testing.

A test that genuinely needs the network marks itself::

    @pytest.mark.network
    def test_against_the_real_thing(): ...

and is deselected in CI with ``-m 'not network'``.
"""

from __future__ import annotations

import pytest

from nova_osint.core import http


@pytest.fixture(autouse=True)
def _no_network(request, monkeypatch):
    """Close the socket for every test that has not asked for it."""
    if request.node.get_closest_marker("network"):
        return

    real = http.Fetcher._once

    def refused(self, url, headers=None, follow_redirects=True, method="GET",
                data=None, timeout=None):
        # Loopback is allowed through: it cannot leave the machine, and one
        # test deliberately dials a dead local port to prove that a transport
        # failure is still logged as a request that was made.
        if url.startswith(("http://127.0.0.1", "http://localhost",
                           "https://127.0.0.1", "https://localhost",
                           "http://[::1]", "https://[::1]")):
            return real(self, url, headers, follow_redirects, method, data,
                        timeout)
        raise AssertionError(
            f"{request.node.name} tried to reach {url}.\n"
            "The suite is offline: use a fixture, a fake fetcher, or mark the "
            "test @pytest.mark.network if it genuinely needs the internet."
        )

    monkeypatch.setattr(http.Fetcher, "_once", refused)
