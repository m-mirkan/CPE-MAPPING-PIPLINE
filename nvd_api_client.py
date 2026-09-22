
from __future__ import annotations
import logging
import random
import time
from collections import deque
from typing import Dict, List, Optional

logger = logging.getLogger("cpe_pipeline.nvd_api_client")

NVD_CPE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


class RateLimiter:
   

    def __init__(self, max_calls: int, period_seconds: float):
        self.max_calls = max_calls
        self.period_seconds = period_seconds
        self._timestamps: deque = deque()

    def wait(self) -> None:
        now = time.monotonic()
        while self._timestamps and now - self._timestamps[0] > self.period_seconds:
            self._timestamps.popleft()
        if len(self._timestamps) >= self.max_calls:
            sleep_for = self.period_seconds - (now - self._timestamps[0]) + 0.05
            if sleep_for > 0:
                logger.debug("Rate limit reached, sleeping %.2fs", sleep_for)
                time.sleep(sleep_for)
        self._timestamps.append(time.monotonic())


class NvdApiClient:
   

    def __init__(self, api_key: Optional[str] = None, max_retries: int = 5,
                 timeout: float = 20.0):
        import requests  # imported lazily so offline-only runs don't need it installed
        self._requests = requests
        self.api_key = api_key
        self.max_retries = max_retries
        self.timeout = timeout
        max_calls = 50 if api_key else 5
        self.rate_limiter = RateLimiter(max_calls=max_calls, period_seconds=30.0)
        self.session = requests.Session()

    def _headers(self) -> Dict[str, str]:
        headers = {"User-Agent": "cpe-pipeline/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _get(self, params: Dict[str, str]) -> Optional[dict]:
        attempt = 0
        while attempt <= self.max_retries:
            self.rate_limiter.wait()
            try:
                resp = self.session.get(
                    NVD_CPE_ENDPOINT, params=params, headers=self._headers(),
                    timeout=self.timeout,
                )
            except self._requests.RequestException as e:
                attempt += 1
                backoff = self._backoff_seconds(attempt)
                logger.warning("Request error (%s), retrying in %.1fs [%d/%d]",
                                e, backoff, attempt, self.max_retries)
                time.sleep(backoff)
                continue

            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (403, 429):
                attempt += 1
                backoff = self._backoff_seconds(attempt)
                logger.warning(
                    "NVD API throttled/forbidden (status %d), backing off %.1fs [%d/%d]",
                    resp.status_code, backoff, attempt, self.max_retries,
                )
                time.sleep(backoff)
                continue
        
            logger.warning("NVD API returned status %d for params=%s", resp.status_code, params)
            return None
        logger.error("Giving up on NVD API request after %d retries: %s", self.max_retries, params)
        return None

    @staticmethod
    def _backoff_seconds(attempt: int) -> float:
        base = min(60.0, (2 ** attempt))
        return base + random.uniform(0, 1.0)


    def get_by_cpe_name(self, cpe_name: str) -> List[dict]:
        """Exact lookup: does this fully-qualified CPE name exist?"""
        data = self._get({"cpeMatchString": cpe_name})
        return data.get("products", []) if data else []

    def search_keyword(self, keyword: str, limit: int = 25) -> List[dict]:
        """Live analogue of LocalCpeDictionary.search_by_keyword."""
        data = self._get({"keywordSearch": keyword, "resultsPerPage": str(limit)})
        return data.get("products", []) if data else []
