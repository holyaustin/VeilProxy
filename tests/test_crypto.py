import itertools

import pytest
from hypothesis import given, settings, strategies as st

from veil import crypto


def test_shamir_all_threshold_subsets(backend):
    m, _ = crypto.get_backend(backend)
    secret = bytes(range(32))
    sh = m.split_secret(secret, 5, 3)
    for combo in itertools.combinations(sh, 3):
        assert m.combine_shares(list(combo)) == secret
    with pytest.raises(ValueError, match="insufficient"):
        m.combine_shares(sh[:2])


def test_shares_reject_duplicates_corruption_and_mixing(backend):
    m, _ = crypto.get_backend(backend)
    sh = m.split_secret(b"abcdefgh", 4, 2)
    with pytest.raises(ValueError, match="duplicate"):
        m.combine_shares([sh[0], sh[0]])
    bad = sh[0][:-1] + ("0" if sh[0][-1] != "0" else "1")
    with pytest.raises(ValueError, match="checksum"):
        m.combine_shares([bad, sh[1]])
    other = m.split_secret(b"abcdefgh", 4, 3)
    with pytest.raises(ValueError, match="different"):
        m.combine_shares([sh[0], other[1]])
    with pytest.raises(ValueError):
        m.split_secret(b"x", 2, 3)


@settings(max_examples=60, deadline=None)
@given(secret=st.binary(min_size=1, max_size=64), data=st.data())
def test_shamir_property_pure_and_rust(secret, data):
    k = data.draw(st.integers(2, 6))
    n = data.draw(st.integers(k, 8))
    for name in ("python", "rust"):
        try:
            m, _ = crypto.get_backend(name)
        except RuntimeError:
            continue
        sh = m.split_secret(secret, n, k)
        pick = data.draw(st.permutations(sh))[:k]
        assert m.combine_shares(list(pick)) == secret


def test_keyholder_unlock_lock_and_wrong_shares(backend):
    m, _ = crypto.get_backend(backend)
    sh, chk = m.generate_shares(5, 3)
    other, _ = m.generate_shares(5, 3)
    h = m.KeyHolder()
    assert not h.is_unlocked()
    with pytest.raises(ValueError):
        h.unlock(sh[:2], chk)  # below threshold
    assert h.unlock([sh[0], sh[1], other[2]], chk) is False  # mixed splits -> key-check fails
    assert h.unlock([sh[4], sh[0], sh[2]], chk) is True
    assert h.is_unlocked()
    h.lock()
    assert not h.is_unlocked()
    with pytest.raises(ValueError):
        h.encrypt("s", b"x", b"")


def test_aead_binding_tamper_isolation(backend):
    m, _ = crypto.get_backend(backend)
    sh, chk = m.generate_shares(3, 2)
    h = m.KeyHolder()
    assert h.unlock(sh[:2], chk)
    ct = bytes(h.encrypt("sess", b"sk-secret", b"sess|[APIKEY_1]"))
    assert bytes(h.decrypt("sess", ct, b"sess|[APIKEY_1]")) == b"sk-secret"
    for args in (("sess", ct, b"sess|[APIKEY_2]"), ("other", ct, b"sess|[APIKEY_1]")):
        with pytest.raises(ValueError):
            h.decrypt(*args)
    tampered = ct[:-1] + bytes([ct[-1] ^ 1])
    with pytest.raises(ValueError):
        h.decrypt("sess", tampered, b"sess|[APIKEY_1]")
    assert bytes(h.encrypt("sess", b"sk-secret", b"x")) != bytes(h.encrypt("sess", b"sk-secret", b"x"))
    assert h.tag("a", b"v") == h.tag("a", b"v") != h.tag("b", b"v")


def test_rust_and_python_backends_are_interoperable():
    try:
        rust, _ = crypto.get_backend("rust")
    except RuntimeError:
        pytest.skip("rust backend not built")
    py, _ = crypto.get_backend("python")
    for gen, other in ((rust, py), (py, rust)):
        sh, chk = gen.generate_shares(5, 3)
        a, b = gen.KeyHolder(), other.KeyHolder()
        assert a.unlock(sh[:3], chk) and b.unlock(sh[2:], chk)
        ct = bytes(a.encrypt("s", b"hello", b"aad"))
        assert bytes(b.decrypt("s", ct, b"aad")) == b"hello"
        assert a.tag("s", b"x") == b.tag("s", b"x")
