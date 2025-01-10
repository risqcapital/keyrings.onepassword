import asyncio
import logging
import os

from jaraco.classes import properties
from keyring.backend import KeyringBackend
from keyring.credentials import Credential

from onepassword.client import Client

from .credential import OnePasswordCredential
from .version import __version__

_AUTH_ENV_VAR = "OP_SERVICE_ACCOUNT_TOKEN"
_BACKEND_VAULT_ENV_VAR = "OP_KEYRING_BACKEND_VAULT"
_DEFAULT_KEYRING_VAULT = "keyring"


async def get_client() -> Client:
    return await Client.authenticate(
        auth=os.getenv(_AUTH_ENV_VAR),
        integration_name="keyrings.onepassword",
        integration_version=__version__,
    )


def get_backend_vault_name() -> str:
    return os.getenv(_BACKEND_VAULT_ENV_VAR, _DEFAULT_KEYRING_VAULT)


async def vault_exists() -> bool:
    client = await get_client()
    vault_name = get_backend_vault_name()
    async for vault in await client.vaults.list_all():
        if vault.title == vault_name:
            return True
    return False


class OnePasswordKeyring(KeyringBackend):
    """A keyring which uses a 1Password vault as the backend."""

    def __init__(self) -> None:
        super().__init__()  # type: ignore[no-untyped-call]
        self.client = asyncio.run(get_client())

    @classmethod
    @properties.classproperty
    def priority(cls) -> float:
        if not os.getenv(_AUTH_ENV_VAR):
            raise RuntimeError(
                f"Requires onepassword service account token to be set via {_AUTH_ENV_VAR}"
            )
        return 20

    @property
    def vault(self) -> str:
        return os.getenv(_BACKEND_VAULT_ENV_VAR, _DEFAULT_KEYRING_VAULT)

    async def _get_attribute(self, service: str, attribute: str) -> str | None:
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
