from keyring.credentials import Credential


class OnePasswordCredential(Credential):
    def __init__(self, username: str | None, password: str) -> None:
        self._username = username
        self._password = password

    @property
    def username(self) -> str:
        return self._username or ""

    @property
    def password(self) -> str:
        return self._password
