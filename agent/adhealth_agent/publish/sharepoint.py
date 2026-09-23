"""SharePoint document library upload via Microsoft Graph, app-only.

Least privilege: register an Entra app with the Graph application permission **Sites.Selected** and grant it
`write` on the single target site only. Prefer a certificate credential over a client secret.
"""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import quote

import requests

from ..config import SharePointConfig, env_secret
from . import write_outbox

log = logging.getLogger(__name__)
GRAPH = "https://graph.microsoft.com/v1.0"
SIMPLE_UPLOAD_LIMIT = 4 * 1024 * 1024
CHUNK = 5 * 320 * 1024  # multiple of 320 KiB as Graph requires


class SharePointPublisher:
    def __init__(self, cfg: SharePointConfig, outbox: Path, dry_run: bool):
        self.cfg = cfg
        self.outbox = outbox
        self.dry_run = dry_run or not cfg.enabled
        self._token: str | None = None

    def _get_token(self) -> str:
        if self._token:
            return self._token
        import msal  # optional dependency: pip install adhealth-agent[graph]

        tenant, client = env_secret(self.cfg.tenant_id_env), env_secret(self.cfg.client_id_env)
        if not tenant or not client:
            raise RuntimeError("Graph tenant/client id environment variables are not set")
        cert_path, thumb = env_secret(self.cfg.cert_path_env), env_secret(self.cfg.cert_thumbprint_env)
        if cert_path and thumb:
            credential = {"private_key": Path(cert_path).read_text(encoding="utf-8"), "thumbprint": thumb}
        else:
            credential = env_secret(self.cfg.client_secret_env)
            if not credential:
                raise RuntimeError("No Graph credential: set certificate (preferred) or client secret environment variables")
        app = msal.ConfidentialClientApplication(client, authority=f"https://login.microsoftonline.com/{tenant}", client_credential=credential)
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" not in result:
            raise RuntimeError(f"Graph token request failed: {result.get('error')}")
        self._token = result["access_token"]
        return self._token

    def upload(self, remote_path: str, content: bytes) -> str:
        """Upload to <site drive>/<folder>/<remote_path>. Returns webUrl (or dry-run path)."""
        if self.dry_run:
            p = write_outbox(self.outbox, f"sharepoint_{remote_path.replace('/', '__')}", content)
            log.info("DRY-RUN SharePoint upload written to %s", p)
            return f"dry-run:{p}"
        if not self.cfg.site_id:
            raise RuntimeError("sharepoint.site_id is not configured")
        full = f"{self.cfg.folder.strip('/')}/{remote_path.lstrip('/')}"
        item = f"{GRAPH}/sites/{self.cfg.site_id}/drive/root:/{quote(full)}"
        headers = {"Authorization": f"Bearer {self._get_token()}"}
        if len(content) <= SIMPLE_UPLOAD_LIMIT:
            r = requests.put(f"{item}:/content", data=content, headers=headers, timeout=60)
            r.raise_for_status()
            return r.json().get("webUrl", "")
        sess = requests.post(f"{item}:/createUploadSession", headers=headers, timeout=60,
                             json={"item": {"@microsoft.graph.conflictBehavior": "replace"}})
        sess.raise_for_status()
        upload_url = sess.json()["uploadUrl"]  # pre-authenticated; do not send the bearer token
        total = len(content)
        resp = None
        for start in range(0, total, CHUNK):
            chunk = content[start:start + CHUNK]
            end = start + len(chunk) - 1
            resp = requests.put(upload_url, data=chunk, timeout=120,
                                headers={"Content-Length": str(len(chunk)), "Content-Range": f"bytes {start}-{end}/{total}"})
            resp.raise_for_status()
        return resp.json().get("webUrl", "") if resp is not None else ""
