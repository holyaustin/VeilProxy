"""VeilProxy TUI: three panes (what you see / what the provider receives / vault + detections)."""
from __future__ import annotations

import asyncio
import json
import re
import os
import time
from pathlib import Path

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Input, Label, RichLog, Static

from .client import GatewayClient, GatewayError

PH = re.compile(r"\[[A-Z][A-Z0-9]*_\d+\]")
DEMO_PROMPTS = [
    "Draft a short email to ada.obi@example.com. Mention the invoice is paid with card 4111 1111 1111 1111 "
    "and our deploy key is sk-proj-Q8x2LmN4vB7cR1tY9uZ3aW5eD6fG0hJk. My phone is 08031234567.",
    "Summarise this config for a teammate: DATABASE_URL=postgres://admin:s3cr3tpw@db.internal/prod  password: Tr0ub4dor&3xx",
    "Reply to that email with a friendlier tone.",
    "Our IBAN is GB82 WEST 1234 5698 7654 32 and AWS key AKIAIOSFODNN7EXAMPLE, is that safe to share?",
]  # all values are FAKE test data

HELP = (
    "/demo [1-4]        send a built-in FAKE-data test prompt (no pasting needed)\n"
    "/unlock            ask the custodians for shards (threshold approval)\n"
    "/shards S1 S2 ...  unlock by pasting shards manually\n"
    "/lock              wipe the master key from memory now\n"
    "/copy [you|wire|all] copy a pane to the clipboard and save it to a file (/save = file only)\n"
    "/models            list models available through OmniRoute\n"
    "/model ID          choose the model (e.g. /model openai/gpt-4o-mini)\n"
    "/session NAME      switch conversation/session\n"
    "/clear             clear the conversation\n"
    "/help              this help    |    Ctrl+U unlock · Ctrl+L lock · Ctrl+Q quit"
)


def with_placeholders(s: str, base: str = "") -> Text:
    t = Text(base, overflow="fold", no_wrap=False)
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
    #col-side { width: 30%; min-width: 26; max-width: 40; }
    .col-title { text-style: bold; color: $accent; }
    #live { height: auto; max-height: 8; color: $success; }
    #vault { height: auto; }
    #items { height: 1fr; }
    #prompt { dock: bottom; }
    /* vertical scrolling only: long lines word-wrap (long unbroken tokens fold) instead of scrolling sideways */
    RichLog { overflow-x: hidden; overflow-y: auto; width: 100%; scrollbar-gutter: stable; }
    #vault, #live { width: 100%; }
    #items { overflow-x: hidden; }
    """
    BINDINGS = [
        Binding("ctrl+u", "unlock", "Unlock"),
        Binding("ctrl+l", "lock", "Lock"),
        Binding("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self, client: GatewayClient, model: str = "", session: str = "tui", save_dir: Path | None = None):
        super().__init__()
        self.client = client
        self.model = model
        self.session = session
        self.history: list[dict] = []
        self.busy = False
        self.transcript_you: list[str] = []
        self.transcript_wire: list[str] = []
        self.last_error = ""
        self._shown_id = 0
        self._you_items: list[Text] = []
        self._wire_items: list[Text] = []
        self._rewrap_timer = None
        self.save_dir = Path(save_dir) if save_dir else Path(os.environ.get("VEIL_HOME") or Path.home() / ".veilproxy") / "transcripts"

    # ------------------------------------------------------------------ layout
    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="cols"):
            with Vertical(classes="col", id="col-you"):
                yield Label("① WHAT YOU SEE  (local, real values)", classes="col-title")
                yield RichLog(id="you", wrap=True, markup=False, highlight=False, min_width=1)
                yield Static("", id="live")
            with Vertical(classes="col", id="col-wire"):
                yield Label("② WHAT THE PROVIDER RECEIVES", classes="col-title")
                yield RichLog(id="wire", wrap=True, markup=False, highlight=False, min_width=1)
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

    def log_you(self, t: Text) -> None:
        self._you_items.append(t)
        self.you().write(t)

    def log_wire(self, t: Text) -> None:
        self._wire_items.append(t)
        self.wire().write(t)

    def on_resize(self, event) -> None:
        """RichLog keeps old lines at their old wrap width, so re-wrap everything after a resize
        (keeps the boxes vertical-scroll-only when the window is resized or un-maximised)."""
        if self._rewrap_timer is not None:
            self._rewrap_timer.stop()
        self._rewrap_timer = self.set_timer(0.2, self.rewrap)

    def rewrap(self) -> None:
        for log, items in ((self.you(), self._you_items), (self.wire(), self._wire_items)):
            log.clear()
            for t in items:
                log.write(t)

    def note(self, msg: str, style: str = "dim") -> None:
        self.transcript_you.append(msg)
        self.log_you(Text(msg, style=style, overflow="fold", no_wrap=False))

    def err(self, msg: str) -> None:
        self.last_error = msg
        self.transcript_you.append("ERROR: " + msg)
        self.log_you(Text("✖ " + msg, style="bold red", overflow="fold", no_wrap=False))

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
        elif cmd == "/demo":
            try:
                n = int(args[0]) if args else 1
                prompt = DEMO_PROMPTS[n - 1]
            except (ValueError, IndexError):
                self.note("usage: /demo 1..4")
                return
            if self.busy:
                self.note("still waiting for the previous reply…")
            else:
                self.run_worker(self.chat(prompt), exclusive=False)
        elif cmd == "/unlock":
            await self.action_unlock()
        elif cmd == "/shards":
            res = await self.client.unlock(args)
            self.report_unlock(res)
            await self.refresh_status()
        elif cmd in ("/copy", "/save"):
            which = args[0] if args and args[0] in ("you", "wire", "all") else "all"
            you = "\n\n".join(self.transcript_you)
            wire = "\n".join(self.transcript_wire)
            text = {"you": you, "wire": wire,
                    "all": f"=== WHAT YOU SEE (real values) ===\n{you}\n\n=== WHAT THE PROVIDER RECEIVED ===\n{wire}\n"}[which]
            self.save_dir.mkdir(parents=True, exist_ok=True)
            path = self.save_dir / time.strftime("transcript-%Y%m%d-%H%M%S.txt")
            path.write_text(text)
            try:
                path.chmod(0o600)
            except OSError:
                pass
            if cmd == "/copy":
                try:
                    self.copy_to_clipboard(text)
                except Exception:
                    pass
            warn = "  ⚠ contains real values" if which != "wire" else ""
            self.note(f"{'copied (if your terminal allows) and ' if cmd == '/copy' else ''}saved: {path}{warn}")
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
            self._you_items.clear()
            self._wire_items.clear()
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
    async def latest_audit_id(self) -> int:
        try:
            rows = await self.client.audit(1, self.session)
            return rows[0]["id"] if rows else 0
        except GatewayError:
            return 0

    async def chat(self, text: str) -> None:
        self.busy = True
        live = self.query_one("#live", Static)
        prev = await self.latest_audit_id()
        watcher = asyncio.create_task(self.watch_wire(prev))
        self.history.append({"role": "user", "content": text})
        self.transcript_you.append("YOU: " + text)
        self.log_you(Text("you › ", style="bold cyan", overflow="fold") + Text(text, overflow="fold"))
        live.update(Text("waiting for the model…", style="dim"))
        reply = ""
        ok = True
        try:
            async for piece in self.client.chat_stream(self.history, self.model, self.session):
                reply += piece
                live.update(Text("assistant › ", style="bold green", overflow="fold") + Text(reply, overflow="fold"))
            if not reply:
                reply = "(empty reply: the model sent no visible text; try /model with a non-thinking model)"
            self.history.append({"role": "assistant", "content": reply})
            self.transcript_you.append("ASSISTANT: " + reply)
            self.log_you(Text("assistant › ", style="bold green", overflow="fold") + Text(reply, overflow="fold"))
        except GatewayError as e:
            ok = False
            self.history.pop()
            self.err(str(e))
        finally:
            live.update("")
            self.busy = False
        if not watcher.done():
            watcher.cancel()
        await self.finish_wire(prev)

    async def watch_wire(self, prev_id: int) -> None:
        """Show what the provider received as soon as the request is logged (before the reply ends)."""
        for _ in range(240):  # up to ~2 minutes
            await asyncio.sleep(0.4)
            try:
                rows = await self.client.audit(1, self.session)
            except GatewayError:
                continue
            if rows and rows[0]["id"] > prev_id:
                self.render_wire(rows[0])
                return

    async def finish_wire(self, prev_id: int) -> None:
        try:
            rows = await self.client.audit(1, self.session)
        except GatewayError:
            return
        if not rows or rows[0]["id"] <= prev_id:
            return  # request never reached the provider (e.g. vault locked): nothing to show
        a = rows[0]
        if self._shown_id != a["id"]:
            self.render_wire(a)
        tail = f"   ↳ status {a.get('status')}"
        if a.get("usage"):
            tail += f" · tokens {a['usage'].get('total_tokens')}"
        if a.get("latency_ms") is not None:
            tail += f" · {a['latency_ms']} ms"
        self.log_wire(Text(tail, style="dim", overflow="fold"))
        self.transcript_wire.append(tail)

    def render_wire(self, a: dict) -> None:
        self._shown_id = a["id"]
        if not a.get("outbound"):
            msg = "⛔ " + (a.get("note") or "request blocked locally") + f"  (status {a.get('status')})"
            self.log_wire(Text(msg, style="bold red"))
            self.transcript_wire.append(msg)
            return
        out = json.loads(a["outbound"])
        head = f"── {time.strftime('%H:%M:%S')}  model={a.get('model')}  (sent to OmniRoute)"
        self.log_wire(Text(head, style="bold", overflow="fold"))
        self.transcript_wire.append(head)
        for m in out.get("messages", []):
            c = m.get("content")
            s = c if isinstance(c, str) else json.dumps(c, ensure_ascii=False)
            self.log_wire(with_placeholders(s, f"{m.get('role')}: "))
            self.transcript_wire.append(f"{m.get('role')}: {s}")
        tbl = self.query_one("#items", DataTable)
        tbl.clear()
        for d in a.get("detections", []):
            tbl.add_row(d["placeholder"], d["kind"], str(d["length"]), "yes" if d["new"] else "")
        if a.get("note"):
            self.log_wire(Text("⚑ " + a["note"], style="yellow"))
