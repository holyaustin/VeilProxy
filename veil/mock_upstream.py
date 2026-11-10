"""A MOCK of an OmniRoute-style OpenAI-compatible server, for offline tests and demos only.

It is NOT a language model: it records exactly what it receives and answers by echoing any
placeholders it finds. Real demos must use real OmniRoute.  Run: veil mock-omniroute
"""
from __future__ import annotations

import json
import re

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

PH = re.compile(r"\[[A-Z][A-Z0-9]*_\d+\]")


def build_fake_upstream(log: list) -> FastAPI:
    app = FastAPI(title="mock-omniroute")

    @app.get("/v1/models")
    async def models():
        return {"object": "list", "data": [{"id": "mock/echo-a"}, {"id": "mock/echo-b"}, {"id": "fake/model-a"}]}

    @app.post("/v1/chat/completions")
    async def chat(request: Request):
        body = await request.json()
        log.append(body)
        last_user = next((m for m in reversed(body["messages"]) if m["role"] == "user"), {"content": ""})
        c = last_user["content"]
        text = c if isinstance(c, str) else json.dumps(c)
        if "FORCE_500" in text:
            return JSONResponse({"error": {"message": "boom", "type": "server_error"}}, status_code=500)
        found = PH.findall(text)
        reply = "ACK " + (" ".join(found) if found else "nothing-sensitive") + "."
        if not body.get("stream"):
            return {"id": "chatcmpl-test", "object": "chat.completion", "model": body["model"],
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": reply},
                                 "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12}}

        async def gen():
            def ev(d):
                return "data: " + json.dumps(d) + "\n\n"

            base = {"id": "chatcmpl-stream", "object": "chat.completion.chunk", "model": body["model"]}
            yield ev({**base, "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]})
            for i in range(0, len(reply), 3):  # 3-char chunks split placeholders on purpose
                yield ev({**base, "choices": [{"index": 0, "delta": {"content": reply[i:i + 3]}, "finish_reason": None}]})
            yield ev({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
            yield "data: [DONE]\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    return app


def app_factory() -> FastAPI:
    return build_fake_upstream([])
