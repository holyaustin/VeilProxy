import httpx

from tests.conftest import make_env
from veil.tui.app import VeilApp
from veil.tui.client import GatewayClient

EMAIL, KEY = "bob@example.com", "sk-proj-abcdefghijklmnopqrstuvwx1234"


async def test_tui_end_to_end(tmp_path):
    env = make_env(tmp_path)
    gc = GatewayClient("http://veil", env.admin["X-Veil-Admin"], transport=httpx.ASGITransport(app=env.app))
    app = VeilApp(gc, model="fake/model-a", save_dir=tmp_path / "tr")
    async with app.run_test(size=(170, 50)) as pilot:
        await pilot.pause()
        prompt = app.query_one("#prompt")

        async def send(text):
            prompt.value = text
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()

        await send(f"hello {EMAIL}")                       # locked -> clear error, nothing sent
        assert "locked" in app.last_error.lower() and env.log == []

        await send("/shards " + " ".join(env.shares[:2]))  # 2 shards -> refused
        assert "insufficient" in app.last_error
        await send("/shards " + " ".join(env.shares[:3]))  # 3 shards -> unlocked
        assert any("unlocked" in t for t in app.transcript_you)

        await send(f"please email {EMAIL} using key {KEY}")
        you = "\n".join(app.transcript_you)
        wire = "\n".join(app.transcript_wire)
        assert EMAIL in you and KEY in you                  # user sees real values
        assert "[EMAIL_1]" in wire and "[APIKEY_1]" in wire  # provider pane shows placeholders
        assert EMAIL not in wire and KEY not in wire
        assert EMAIL not in str(env.log) and KEY not in str(env.log)
        assert app.query_one("#items").row_count == 2

        await send("/demo 1")                               # built-in prompt, no pasting
        wire = "\n".join(app.transcript_wire)
        assert "[EMAIL_" in wire and "ada.obi@example.com" not in wire and "4111 1111" not in wire

        await send("/copy wire")
        saved = list((tmp_path / "tr").glob("transcript-*.txt"))
        assert saved and "[EMAIL_1]" in saved[0].read_text() and "ada.obi@example.com" not in saved[0].read_text()

        await send("/lock")
        await pilot.pause()
        await send("anything")
        assert "locked" in app.last_error.lower()
    await gc.aclose()
    await env.client.aclose()


async def test_panes_wrap_instead_of_scrolling_sideways(tmp_path):
    """Boxes scroll vertically only: long lines (even unbroken ones) fold onto the next line, nothing is cut."""
    env = make_env(tmp_path)
    gc = GatewayClient("http://veil", env.admin["X-Veil-Admin"], transport=httpx.ASGITransport(app=env.app))
    app = VeilApp(gc, model="fake/model-a", save_dir=tmp_path / "tr")
    long_token = "A" * 150
    async with app.run_test(size=(100, 40)) as pilot:          # narrow: columns are ~27 cells wide
        await pilot.pause()
        prompt = app.query_one("#prompt")

        async def send(text):
            prompt.value = text
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause(0.3)

        await send("/shards " + " ".join(env.shares[:3]))
        await send(f"mail {EMAIL} key {KEY} and {long_token} end")
        for sel in ("#you", "#wire"):
            w = app.query_one(sel)
            assert w.max_scroll_x == 0, f"{sel} scrolls horizontally"
            assert w.virtual_size.width <= w.size.width
        rendered = "".join(strip.text for strip in app.query_one("#you").lines)
        assert rendered.count("A") >= 150                      # folded onto several lines, not truncated
        await pilot.resize_terminal(60, 40)                    # even narrower after the fact
        await pilot.pause(0.8)
        for sel in ("#you", "#wire"):
            assert app.query_one(sel).max_scroll_x == 0
        assert "".join(st.text for st in app.query_one("#you").lines).count("A") >= 150   # still intact
    await gc.aclose()
    await env.client.aclose()
