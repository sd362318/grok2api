from __future__ import annotations

from typing import Optional, Dict, Any

from curl_cffi import requests
from curl_cffi.requests import AsyncSession

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


class NsfwSettingsService:
    """开启 NSFW 相关设置（线程安全，无全局状态）。"""

    def __init__(self, cf_clearance: str = ""):
        self.cf_clearance = (cf_clearance or "").strip()

    def _build_request_params(
        self,
        sso: str,
        sso_rw: str,
        impersonate: str,
        user_agent: Optional[str] = None,
        cf_clearance: Optional[str] = None,
        timeout: int = 15,
    ) -> tuple[str, dict, dict, bytes, str, int]:
        """Build common request parameters for NSFW enablement."""
        url = "https://grok.com/auth_mgmt.AuthManagement/UpdateUserFeatureControls"

        cookies = {
            "sso": sso,
            "sso-rw": sso_rw,
        }
        clearance = (cf_clearance if cf_clearance is not None else self.cf_clearance).strip()
        if clearance:
            cookies["cf_clearance"] = clearance

        headers = {
            "content-type": "application/grpc-web+proto",
            "origin": "https://grok.com",
            "referer": "https://grok.com/?_s=data",
            "x-grpc-web": "1",
            "user-agent": user_agent or DEFAULT_USER_AGENT,
        }

        data = (
            b"\x00\x00\x00\x00"
            b"\x20"
            b"\x0a\x02\x10\x01"
            b"\x12\x1a"
            b"\x0a\x18"
            b"always_show_nsfw_content"
        )

        imp = impersonate or "chrome120"
        return url, headers, cookies, data, imp, timeout

    @staticmethod
    def _parse_response(response) -> Dict[str, Any]:
        """Parse a gRPC-Web response into a standard result dict."""
        hex_reply = response.content.hex()
        grpc_status = response.headers.get("grpc-status")

        error = None
        ok = response.status_code == 200 and (grpc_status in (None, "0"))
        if response.status_code == 403:
            error = "403 Forbidden"
        elif response.status_code != 200:
            error = f"HTTP {response.status_code}"
        elif grpc_status not in (None, "0"):
            error = f"gRPC {grpc_status}"

        return {
            "ok": ok,
            "hex_reply": hex_reply,
            "status_code": response.status_code,
            "grpc_status": grpc_status,
            "error": error,
        }

    def enable_nsfw(
        self,
        sso: str,
        sso_rw: str,
        impersonate: str,
        user_agent: Optional[str] = None,
        cf_clearance: Optional[str] = None,
        timeout: int = 15,
    ) -> Dict[str, Any]:
        """
        启用 always_show_nsfw_content (synchronous).
        返回: {ok, hex_reply, status_code, grpc_status, error}
        """
        if not sso:
            return {"ok": False, "hex_reply": "", "status_code": None, "grpc_status": None, "error": "缺少 sso"}
        if not sso_rw:
            return {"ok": False, "hex_reply": "", "status_code": None, "grpc_status": None, "error": "缺少 sso-rw"}

        url, headers, cookies, data, imp, timeout = self._build_request_params(
            sso, sso_rw, impersonate, user_agent, cf_clearance, timeout,
        )
        try:
            response = requests.post(url, headers=headers, cookies=cookies, data=data, impersonate=imp, timeout=timeout)
            return self._parse_response(response)
        except Exception as e:
            return {"ok": False, "hex_reply": "", "status_code": None, "grpc_status": None, "error": str(e)}

    async def enable_nsfw_async(
        self,
        session: AsyncSession,
        sso: str,
        sso_rw: str,
        impersonate: str,
        user_agent: Optional[str] = None,
        cf_clearance: Optional[str] = None,
        timeout: int = 15,
    ) -> Dict[str, Any]:
        """
        启用 always_show_nsfw_content (async, reuses session).
        返回: {ok, hex_reply, status_code, grpc_status, error}
        """
        if not sso:
            return {"ok": False, "hex_reply": "", "status_code": None, "grpc_status": None, "error": "缺少 sso"}
        if not sso_rw:
            return {"ok": False, "hex_reply": "", "status_code": None, "grpc_status": None, "error": "缺少 sso-rw"}

        url, headers, cookies, data, imp, timeout = self._build_request_params(
            sso, sso_rw, impersonate, user_agent, cf_clearance, timeout,
        )
        try:
            response = await session.post(
                url, headers=headers, cookies=cookies, data=data, impersonate=imp, timeout=timeout,
            )
            return self._parse_response(response)
        except Exception as e:
            return {"ok": False, "hex_reply": "", "status_code": None, "grpc_status": None, "error": str(e)}
