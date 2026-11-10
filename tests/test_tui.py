import httpx

from tests.conftest import make_env
from veil.tui.app import VeilApp
from veil.tui.client import GatewayClient

EMAIL, KEY = "bob@example.com", "sk-proj-abcdefghijklmnopqrstuvwx1234"


async def test_tui_end_to_end(tmp_path):
    env = make_env(tmp_path)
    gc = GatewayClient("http://veil", env.admin["X-Veil-Admin"], transport=httpx.ASGITransport(app=env.app))
    app = VeilApp(gc, model="fake/model-a")
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

        await send("/lock")
        await pilot.pause()
        await send("anything")
        assert "locked" in app.last_error.lower()
    await gc.aclose()
    await env.client.aclose()
