# define a new keyring class which extends the KeyringBackend
import asyncio
import os

from jaraco.classes import properties
from keyring.backend import KeyringBackend

from onepassword.client import Client

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

    @classmethod
    @properties.classproperty
    def priority(cls) -> float:
        if not os.getenv(_AUTH_ENV_VAR):
            raise RuntimeError(
                f"Requires onepassword service account token to be set via {_AUTH_ENV_VAR}"
            )
        # TODO: Not sure if we keep this lookup of the vault here, since it slows down initialisation
        if not asyncio.run(vault_exists()):
            raise RuntimeError(
                f"Cannot find 1Password vault {get_backend_vault_name()}"
            )

        return 20

    @property
    def vault(self) -> str:
        return os.getenv(_BACKEND_VAULT_ENV_VAR, _DEFAULT_KEYRING_VAULT)

    async def _get_password(self, service: str) -> str:
        client = await get_client()
        return await client.secrets.resolve(f"op://{self.vault}/{service}/password")

    def set_password(self, service: str, username: str, password: str) -> None:
        pass

    def get_password(self, service: str, username: str) -> str | None:
        return asyncio.run(self._get_password(service))

    def delete_password(self, service: str, username: str) -> None:
        pass
