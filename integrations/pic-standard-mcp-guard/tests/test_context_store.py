"""Unit tests for InMemoryContextStore lifecycle, tombstones, and validation.

Two store-related guarantees are exercised at the coordinator level instead of here,
because they are classification/precedence properties of run(), not the store API:
a custom-store transition failure staying classified PIC-allowed, and an overlong
request id being rejected before any store.reserve() call (see test_coordinator.py).
"""

from __future__ import annotations

import threading

import pytest

import pic_trace_guard as g


def test_reserve_transition_consume_happy_path():
    store = g.InMemoryContextStore()
    store.reserve("r1")
    assert store.peek("r1") == {"state": "reserved"}
    store.transition("r1", "reserved", "bridged", raw=b"x", bridge={"a": 1})
    assert store.peek("r1")["state"] == "bridged"
    ctx = store.consume("r1", expected="bridged")
    assert ctx["state"] == "bridged" and ctx["raw"] == b"x" and ctx["bridge"] == {"a": 1}
    assert store.peek("r1") == {}  # removed after consume


def test_stored_context_is_detached_from_caller_and_snapshots():
    store = g.InMemoryContextStore()
    store.reserve("p1")
    payload = {"nested": {"value": 1}}
    store.transition("p1", "reserved", "bridged", bridge=payload)
    payload["nested"]["value"] = 2  # mutating the original input must not reach the store
    assert store.peek("p1")["bridge"]["nested"]["value"] == 1
    snapshot = store.peek("p1")
    snapshot["bridge"]["nested"]["value"] = 3  # mutating a snapshot must not reach the store
    assert store.peek("p1")["bridge"]["nested"]["value"] == 1


def test_transition_rejects_state_override():
    store = g.InMemoryContextStore()
    store.reserve("s1")
    with pytest.raises(g.AdapterError):
        store.transition("s1", "reserved", "bridged", state="hacked")
    assert store.peek("s1")["state"] == "reserved"


def test_concurrent_reservations_exactly_one_wins():
    for i in range(5):
        store = g.InMemoryContextStore()
        rid = f"race-{i}"
        results: list[str] = []
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def worker():
            barrier.wait(timeout=5)
            try:
                store.reserve(rid)
                outcome = "ok"
            except g.AdapterError:
                outcome = "rejected"
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
            assert not t.is_alive()
        assert sorted(results) == ["ok", "rejected"]


def test_concurrent_consume_is_one_time():
    for i in range(5):
        store = g.InMemoryContextStore()
        rid = f"consume-race-{i}"
        store.reserve(rid)
        store.transition(rid, "reserved", "bridged")
        results: list[str] = []
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def worker():
            barrier.wait(timeout=5)
            try:
                store.consume(rid, expected="bridged")
                outcome = "ok"
            except g.AdapterError:
                outcome = "rejected"
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
            assert not t.is_alive()
        assert sorted(results) == ["ok", "rejected"]  # finalization consumption is one-time


def test_recent_tombstone_rejects_reuse():
    store = g.InMemoryContextStore()
    store.reserve("t1")
    store.consume("t1", expected="reserved")
    with pytest.raises(g.AdapterError):
        store.reserve("t1")


def test_abandoned_id_is_tombstoned():
    store = g.InMemoryContextStore()
    store.reserve("a1")
    store.abandon_if_active("a1")
    with pytest.raises(g.AdapterError):
        store.reserve("a1")


def test_tombstone_eviction_permits_oldest_reuse():
    store = g.InMemoryContextStore(tombstone_capacity=2)
    for i in range(3):
        store.reserve(f"id{i}")
        store.abandon_if_active(f"id{i}")
    # Tombstones are bounded (cap 2): id0 is evicted and may be reused; id1/id2 still rejected.
    store.reserve("id0")
    assert store.peek("id0") == {"state": "reserved"}
    with pytest.raises(g.AdapterError):
        store.reserve("id1")
    with pytest.raises(g.AdapterError):
        store.reserve("id2")


def test_consume_rejects_wrong_state_non_destructively():
    store = g.InMemoryContextStore()
    store.reserve("c1")
    with pytest.raises(g.AdapterError):
        store.consume("c1", expected="bridged")  # still 'reserved'
    assert store.peek("c1")["state"] == "reserved"  # the failed consume did not remove it


def test_consume_rejects_missing_context():
    store = g.InMemoryContextStore()
    with pytest.raises(g.AdapterError):
        store.consume("missing")


def test_transition_rejects_wrong_expected_state_non_destructively():
    store = g.InMemoryContextStore()
    store.reserve("x1")
    with pytest.raises(g.AdapterError):
        store.transition("x1", "bridged", "consumed")  # expected 'bridged' but is 'reserved'
    assert store.peek("x1")["state"] == "reserved"


def test_transition_rejects_unknown_id():
    store = g.InMemoryContextStore()
    with pytest.raises(g.AdapterError):
        store.transition("nope", "reserved", "bridged")


def test_abandon_if_active_is_idempotent_and_never_raises():
    store = g.InMemoryContextStore()
    store.reserve("a1")
    store.abandon_if_active("a1")   # removes + tombstones
    store.abandon_if_active("a1")   # no-op, must not raise
    store.abandon_if_active("never-reserved")  # no-op, must not raise


def test_request_id_length_boundary():
    store = g.InMemoryContextStore()
    n = g._DEFAULT_MAX_REQUEST_ID_LEN
    store.reserve("a" * n)  # exactly the maximum is accepted
    assert store.peek("a" * n)["state"] == "reserved"
    with pytest.raises(g.AdapterError):
        store.reserve("b" * (n + 1))  # one over is rejected


@pytest.mark.parametrize("bad_id", ["", "a" * (g._DEFAULT_MAX_REQUEST_ID_LEN + 1), 123, None])
def test_reserve_rejects_bad_request_id(bad_id):
    store = g.InMemoryContextStore()
    with pytest.raises(g.AdapterError):
        store.reserve(bad_id)


@pytest.mark.parametrize("bad", [True, 0.5, 0, -1])
def test_store_rejects_bad_tombstone_capacity(bad):
    with pytest.raises(g.AdapterError):
        g.InMemoryContextStore(tombstone_capacity=bad)


@pytest.mark.parametrize("bad", [True, 0.5, 0, -1])
def test_store_rejects_bad_max_request_id_len(bad):
    with pytest.raises(g.AdapterError):
        g.InMemoryContextStore(max_request_id_len=bad)
