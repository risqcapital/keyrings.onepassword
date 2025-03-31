import asyncio
import logging
import os

from jaraco.classes import properties
from keyring.backend import KeyringBackend
from keyring.credentials import Credential

from onepassword.client import Client

from .credential import OnePasswordCredential
from .version import __version__

_AUTH_ENV_VAR = "KEYRING_OP_SERVICE_ACCOUNT_TOKEN"
_BACKEND_VAULT_ENV_VAR = "OP_KEYRING_BACKEND_VAULT"
_DEFAULT_KEYRING_VAULT = "keyring"


async def get_client() -> Client | None:
    if auth_var := os.getenv(_AUTH_ENV_VAR):
        return await Client.authenticate(
            auth=auth_var,
            integration_name="keyrings.onepassword",
            integration_version=__version__,
        )
    else:
        return None


def get_backend_vault_name() -> str:
    return os.getenv(_BACKEND_VAULT_ENV_VAR, _DEFAULT_KEYRING_VAULT)


class OnePasswordKeyring(KeyringBackend):
    """A keyring which uses a 1Password vault as the backend."""

    client: Client | None

    def __init__(self) -> None:
        super().__init__()  # type: ignore[no-untyped-call]
        self.client = asyncio.run(get_client())

    @properties.classproperty
    def priority(cls) -> float:  # noqa: N805
        if not os.getenv(_AUTH_ENV_VAR):
            raise RuntimeError(
                f"Requires onepassword service account token to be set via {_AUTH_ENV_VAR}"
            )
        return 7

    @property
    def vault(self) -> str:
        return os.getenv(_BACKEND_VAULT_ENV_VAR, _DEFAULT_KEYRING_VAULT)

    async def _get_attribute(self, service: str, attribute: str) -> str | None:
        if not self.client:
            return None
        secret_reference = f"op://{self.vault}/{service}/{attribute}"
        try:
            return await self.client.secrets.resolve(secret_reference)
        # TODO: Catch 1Password specific errors only?
        except Exception as ex:
            logging.debug(f"Failed to resolve {secret_reference}: {ex}")
            return None

    async def _get_credential(
        self, service: str, username: str | None
    ) -> Credential | None:
        op_username = await self._get_attribute(service, "username")
        if username is not None and op_username != username:
            return None
        op_password = await self._get_attribute(service, "password")
        if op_password is not None:
            return OnePasswordCredential(
                username=op_username,
                password=op_password,
            )
        return None

    def set_password(self, service: str, username: str, password: str) -> None:
        pass

    def get_password(self, service: str, username: str) -> str | None:
        return asyncio.run(self._get_attribute(service, "password"))

    def delete_password(self, service: str, username: str) -> None:
        pass

    def get_credential(self, service: str, username: str | None) -> Credential | None:
        return asyncio.run(self._get_credential(service, username))
