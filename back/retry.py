import asyncio
import random
from functools import wraps
from typing import Any, Awaitable, Callable

import httpx

from logger import logger

RETRYABLE_HTTP = (502, 503, 504)


def with_retry(max_attempts: int = 3, base_delay: float = 0.5):
    def deco(fn: Callable[..., Awaitable[Any]]):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            last: Exception | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return await fn(*args, **kwargs)
                except httpx.HTTPStatusError as e:
                    if e.response.status_code not in RETRYABLE_HTTP:
                        raise
                    last = e
                except (httpx.TimeoutException, httpx.ConnectError) as e:
                    last = e

                if attempt < max_attempts:
                    delay = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 0.2)
                    logger.warning(
                        "[retry] %s tentativa %s/%s falhou: %s. Aguardando %.2fs",
                        fn.__name__,
                        attempt,
                        max_attempts,
                        last,
                        delay,
                    )
                    await asyncio.sleep(delay)
            raise last

        return wrapper

    return deco


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_attempts: int = 3,
    base_delay: float = 0.5,
    **kwargs,
) -> httpx.Response:
    @with_retry(max_attempts=max_attempts, base_delay=base_delay)
    async def _request():
        response = await client.request(method, url, **kwargs)
        if response.status_code in RETRYABLE_HTTP:
            response.raise_for_status()
        return response

    return await _request()


class RetryingAsyncClient:
    """Wrapper fino para httpx.AsyncClient com retry em falhas transitórias."""

    def __init__(self, client: httpx.AsyncClient, *, max_attempts: int = 3, base_delay: float = 0.5):
        self._client = client
        self._max_attempts = max_attempts
        self._base_delay = base_delay

    def __getattr__(self, name: str):
        return getattr(self._client, name)

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        return await request_with_retry(
            self._client,
            method,
            url,
            max_attempts=self._max_attempts,
            base_delay=self._base_delay,
            **kwargs,
        )

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)
