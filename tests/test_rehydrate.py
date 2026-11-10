from hypothesis import given, strategies as st

from veil.gateway.redact import StreamRehydrator, rehydrate_text

MAP = {"[EMAIL_1]": "bob@example.com", "[APIKEY_2]": "sk-live-xyz"}


def test_rehydrate_known_only():
    assert rehydrate_text("a [EMAIL_1] b [EMAIL_9] c", MAP.get) == "a bob@example.com b [EMAIL_9] c"


@given(text=st.text(alphabet=list("ab [] _1AEILMPYK92"), max_size=80), cut=st.integers(1, 7))
def test_stream_equals_whole_for_any_chunking(text, cut):
    whole = rehydrate_text(text, MAP.get)
    s = StreamRehydrator(MAP.get)
    out = "".join(s.feed(text[i:i + cut]) for i in range(0, len(text), cut)) + s.flush()
    assert out == whole


def test_stream_splits_inside_placeholder():
    s = StreamRehydrator(MAP.get)
    parts = [s.feed(x) for x in ["see [EMA", "IL_", "1] and [APIKEY_2", "] done"]]
    assert "".join(parts) + s.flush() == "see bob@example.com and sk-live-xyz done"
    assert "[EMA" not in parts[0]  # incomplete placeholder never leaks to the client
