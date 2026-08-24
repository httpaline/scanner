import httpx

from models import Evidence, Identity, RequestData, ResponseData

class HttpClient:
    def __init__(self, base_url: str, login_path: str, token_field: str = "token", timeout: float = 10.0):
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout)
        self._login_path = login_path
        self._token_field = token_field
        self._token_cache: dict[str, str] = {}

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        json_body: dict | None = None,
        identity_label: str = "",
    ) -> Evidence:
        response = await self._client.request(method, url, headers=headers, json=json_body)

        request_data = RequestData(
            method=response.request.method,
            url=str(response.request.url),
            headers=dict(response.request.headers),
            body=json_body,
        )

        try:
            response_body = response.json()
        except ValueError:
            response_body = response.text

        response_data = ResponseData(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=response_body,
        )

        return Evidence(request=request_data, response=response_data, identity_label=identity_label)

    async def authenticated_request(
        self,
        method: str,
        url: str,
        identity: Identity,
        json_body: dict | None = None,
    ) -> Evidence:
        token = self._token_cache.get(identity.identity_label)
        if token is None:
            token = await self._login(identity)
            self._token_cache[identity.identity_label] = token

        headers = {"Authorization": f"Bearer {token}"}
        return await self.request(
            method, url, headers=headers, json_body=json_body, identity_label=identity.identity_label
        )

    async def _login(self, identity: Identity) -> str:
        response = await self._client.post(
            self._login_path,
            json={"username": identity.username, "password": identity.password},
        )
        response.raise_for_status()
        return response.json()[self._token_field]
