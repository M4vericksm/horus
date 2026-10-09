import asyncio
import os
import sys

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from retry import request_with_retry


def test_request_with_retry_succeeds_after_retryable_503(monkeypatch):
    async def run():
        calls = 0

        async def no_sleep(_delay):
            return None

        monkeypatch.setattr("retry.asyncio.sleep", no_sleep)
        monkeypatch.setattr("retry.random.uniform", lambda _a, _b: 0)

        async def handler(request):
            nonlocal calls
            calls += 1
            if calls < 3:
                return httpx.Response(503, request=request)
            return httpx.Response(200, json={"ok": True}, request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            response = await request_with_retry(client, "GET", "https://example.test/api")

        assert response.status_code == 200
        assert calls == 3

    asyncio.run(run())


def test_request_with_retry_does_not_retry_non_retryable_500(monkeypatch):
    async def run():
        calls = 0

        async def no_sleep(_delay):
            return None

        monkeypatch.setattr("retry.asyncio.sleep", no_sleep)

        async def handler(request):
            nonlocal calls
            calls += 1
            return httpx.Response(500, request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            response = await request_with_retry(client, "GET", "https://example.test/api")

        assert response.status_code == 500
        assert calls == 1

    asyncio.run(run())
