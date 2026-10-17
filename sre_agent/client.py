"""NetBox REST API 客户端（requests 实现，无额外依赖）。"""
import json

import requests


class NetBoxError(Exception):
    pass


class NetBoxClient:
    def __init__(self, base_url: str, token: str, timeout: int = 30):
        if not token:
            raise NetBoxError("NETBOX_TOKEN 未配置")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    # ------------------------------------------------------------------ 基础
    def _url(self, path: str) -> str:
        return self.base_url + "/api/" + path.strip("/") + "/"

    def _handle(self, resp):
        if resp.status_code == 204:
            return None
        try:
            data = resp.json()
        except ValueError:
            data = {"detail": resp.text[:200].strip()}
        if resp.status_code >= 400:
            detail = data.get("detail") if isinstance(data, dict) else data
            raise NetBoxError("HTTP %s %s -> %s | body=%s" % (
                resp.status_code, resp.request.url, detail, json.dumps(data, ensure_ascii=False)[:500]))
        return data

    def get(self, path: str, params: dict | None = None):
        return self._handle(self.session.get(self._url(path), params=params, timeout=self.timeout))

    def post(self, path: str, payload: dict):
        return self._handle(self.session.post(self._url(path), json=payload, timeout=self.timeout))

    def patch(self, path: str, payload: dict):
        return self._handle(self.session.patch(self._url(path), json=payload, timeout=self.timeout))

    def delete(self, path: str):
        return self._handle(self.session.delete(self._url(path), timeout=self.timeout))

    def get_all(self, path: str, params: dict | None = None) -> list:
        """拉取全部结果（优先 limit=0 一次取完，不支持时自动翻页）。"""
        params = dict(params or {})
        params["limit"] = 0
        data = self.get(path, params)
        results = list(data.get("results", []))
        if len(results) >= data.get("count", 0):
            return results
        # 回退：手动翻页
        out, url = [], self._url(path) + "?" + requests.compat.urlencode(
            {k: v for k, v in params.items() if k != "limit"}
        )
        while url:
            resp = self._handle(self.session.get(url, timeout=self.timeout))
            out.extend(resp.get("results", []))
            url = resp.get("next")
        return out
