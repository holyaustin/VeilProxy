"""VeilProxy TUI: three panes (what you see / what the provider receives / vault + detections)."""
from __future__ import annotations

import json
import re
import time

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Input, Label, RichLog, Static

from .client import GatewayClient, GatewayError

PH = re.compile(r"\[[A-Z][A-Z0-9]*_\d+\]")
HELP = (
    "/unlock            ask the custodians for shards (threshold approval)\n"
    "/shards S1 S2 ...  unlock by pasting shards manually\n"
    "/lock              wipe the master key from memory now\n"
    "/models            list models available through OmniRoute\n"
    "/model ID          choose the model (e.g. /model openai/gpt-4o-mini)\n"
    "/session NAME      switch conversation/session\n"
    "/clear             clear the conversation\n"
    "/help              this help    |    Ctrl+U unlock · Ctrl+L lock · Ctrl+Q quit"
)


def with_placeholders(s: str, base: str = "") -> Text:
    t = Text(base)
    pos = 0
    for m in PH.finditer(s):
        t.append(s[pos : m.start()])
        t.append(m.group(0), style="bold black on yellow")
        pos = m.end()
    t.append(s[pos:])
    return t


class VeilApp(App):
    TITLE = "VeilProxy + ShardKey"
    SUB_TITLE = "secrets never leave this machine"
    CSS = """
    #cols { height: 1fr; }
    .col { width: 1fr; border: round $primary; padding: 0 1; }
    #col-side { width: 38; }
    .col-title { text-style: bold; color: $accent; }
    #live { height: auto; max-height: 8; color: $success; }
    #vault { height: auto; }
    #items { height: 1fr; }
    #prompt { dock: bottom; }
    """
    BINDINGS = [
        Binding("ctrl+u", "unlock", "Unlock"),
        Binding("ctrl+l", "lock", "Lock"),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self, client: GatewayClient, model: str = "", session: str = "tui"):
        super().__init__()
        self.client = client
        self.model = model
        self.session = session
        self.history: list[dict] = []
        self.busy = False
        self.transcript_you: list[str] = []
        self.transcript_wire: list[str] = []
        self.last_error = ""

    # ------------------------------------------------------------------ layout
    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="cols"):
            with Vertical(classes="col", id="col-you"):
                yield Label("① WHAT YOU SEE  (local, real values)", classes="col-title")
                yield RichLog(id="you", wrap=True, markup=False, highlight=False)
                yield Static("", id="live")
            with Vertical(classes="col", id="col-wire"):
                yield Label("② WHAT THE PROVIDER RECEIVES", classes="col-title")
                yield RichLog(id="wire", wrap=True, markup=False, highlight=False)
            with Vertical(classes="col", id="col-side"):
                yield Label("③ SHARDKEY VAULT", classes="col-title")
                yield Static("connecting…", id="vault")
                yield Label("DETECTED IN LAST PROMPT", classes="col-title")
                yield DataTable(id="items")
        yield Input(placeholder="Type a prompt (secrets included) — or /help", id="prompt")
        yield Footer()

    async def on_mount(self) -> None:
        t = self.query_one("#items", DataTable)
        t.add_columns("Placeholder", "Kind", "Len", "New")
        t.cursor_type = "none"
        self.query_one("#prompt", Input).focus()
        self.note("VeilProxy ready. Vault starts LOCKED: use /unlock (custodians) or /shards. /help for commands.")
        await self.refresh_status()
        self.set_interval(2.0, self.refresh_status)

    # ------------------------------------------------------------------ helpers
    def you(self) -> RichLog:
        return self.query_one("#you", RichLog)

    def wire(self) -> RichLog:
        return self.query_one("#wire", RichLog)

    def note(self, msg: str, style: str = "dim") -> None:
        self.transcript_you.append(msg)
        self.you().write(Text(msg, style=style))

    def err(self, msg: str) -> None:
        self.last_error = msg
        self.transcript_you.append("ERROR: " + msg)
        self.you().write(Text("✖ " + msg, style="bold red"))

    async def refresh_status(self) -> None:
        box = self.query_one("#vault", Static)
        try:
            s = await self.client.status()
        except GatewayError as e:
            box.update(Text(f"gateway offline\n{e}", style="red"))
            return
        t = Text()
        if s["unlocked"]:
            t.append("🔓 UNLOCKED\n", style="bold green")
            if s.get("auto_lock_in") is not None:
                t.append(f"auto-lock in {s['auto_lock_in']}s\n")
        else:
            t.append("🔒 LOCKED\n", style="bold red")
        t.append(f"threshold {s['k']}-of-{s['n']}\n" if s.get("k") else "not initialised\n")
        t.append(f"crypto: {s['backend']}\nupstream: {s['upstream']}\n")
        t.append(f"model: {self.model or s.get('default_model') or '(unset)'}\nsession: {self.session}\n")
        lu = s.get("last_unlock") or {}
        for cid, c in sorted((lu.get("custodians") or {}).items()):
            t.append(f"  custodian {cid}: {c['state']}\n")
        box.update(t)

    # ------------------------------------------------------------------ input
    @on(Input.Submitted, "#prompt")
    async def submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.value = ""
        if not text:
            return
        if text.startswith("/"):
            await self.command(text)
        elif self.busy:
            self.note("still waiting for the previous reply…")
        else:
            self.run_worker(self.chat(text), exclusive=False)

    async def command(self, line: str) -> None:
        cmd, *args = line.split()
        if cmd == "/help":
            self.note(HELP)
        elif cmd == "/unlock":
            await self.action_unlock()
        elif cmd == "/shards":
            res = await self.client.unlock(args)
            self.report_unlock(res)
            await self.refresh_status()
        elif cmd == "/lock":
            await self.action_lock()
        elif cmd == "/models":
            try:
                self.note("models: " + ", ".join((await self.client.models())[:40]))
            except GatewayError as e:
                self.err(str(e))
        elif cmd == "/model" and args:
            self.model = args[0]
            self.note(f"model set to {self.model}")
            await self.refresh_status()
        elif cmd == "/session" and args:
            self.session, self.history = args[0], []
            self.note(f"session '{self.session}' (history cleared)")
            await self.refresh_status()
        elif cmd == "/clear":
            self.history = []
            self.you().clear()
            self.wire().clear()
        else:
            self.note("unknown command — /help")

    def report_unlock(self, res: dict) -> None:
        if res.get("ok"):
            self.note(f"🔓 vault unlocked ({res.get('method')})", "bold green")
        else:
            self.err("unlock failed: " + str(res.get("error", res)))

    async def action_unlock(self) -> None:
        self.note("asking custodians for shards… (approve in their terminals)")
        self.report_unlock(await self.client.unlock())
        await self.refresh_status()

    async def action_lock(self) -> None:
        await self.client.lock()
        self.note("🔒 vault locked; master key wiped from memory", "bold red")
        await self.refresh_status()

    # ------------------------------------------------------------------ chat
    async def chat(self, text: str) -> None:
        self.busy = True
        live = self.query_one("#live", Static)
        self.history.append({"role": "user", "content": text})
        self.transcript_you.append("YOU: " + text)
        self.you().write(Text("you › ", style="bold cyan") + Text(text))
        reply = ""
        try:
            async for piece in self.client.chat_stream(self.history, self.model, self.session):
                reply += piece
                live.update(Text("assistant › ", style="bold green") + Text(reply))
            if not reply:
                reply = "(empty reply)"
            self.history.append({"role": "assistant", "content": reply})
            self.transcript_you.append("ASSISTANT: " + reply)
            self.you().write(Text("assistant › ", style="bold green") + Text(reply))
        except GatewayError as e:
            self.history.pop()
            self.err(str(e))
        finally:
            live.update("")
            self.busy = False
        await self.show_provider_view()

    async def show_provider_view(self) -> None:
        try:
            rows = await self.client.audit(1, self.session)
        except GatewayError:
            return
        if not rows:
            return
        a = rows[0]
        out = json.loads(a["outbound"]) if a.get("outbound") else {}
        wire = self.wire()
        head = f"── {time.strftime('%H:%M:%S')}  model={a.get('model')}  status={a.get('status')}"
        if a.get("usage"):
            head += f"  tokens={a['usage'].get('total_tokens')}"
        wire.write(Text(head, style="bold"))
        self.transcript_wire.append(head)
        for m in out.get("messages", []):
            c = m.get("content")
            s = c if isinstance(c, str) else json.dumps(c, ensure_ascii=False)
            wire.write(with_placeholders(s, f"{m.get('role')}: "))
            self.transcript_wire.append(f"{m.get('role')}: {s}")
        tbl = self.query_one("#items", DataTable)
        tbl.clear()
        for d in a.get("detections", []):
            tbl.add_row(d["placeholder"], d["kind"], str(d["length"]), "yes" if d["new"] else "")
        if a.get("note"):
            wire.write(Text("⚑ " + a["note"], style="yellow"))
