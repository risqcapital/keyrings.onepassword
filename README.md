# 1Password Keyring

Implementation of the [Keyring](https://pypi.org/project/keyring/) backend code reading secrets from [1Password](https://1password.com) using [onepassword-sdk](https://github.com/1Password/onepassword-sdk-python).

## Requirements

The 1Password SDK requires a Service Account to authenticate. See the SDKs [Get started](https://github.com/1Password/onepassword-sdk-python/tree/v0.1.5?tab=readme-ov-file#-get-started) section for details

## Installation and configuration

```
pip install keyrings.onepassword
```

## Usage

The backend will only activate if the `OP_SERVICE_ACCOUNT_TOKEN` environment variable is set. By default, the backend will look for secrets in a vault called `keyring`; this can be configured via the `OP_KEYRING_BACKEND_VAULT` environment variable.
Use as a normal keyring backend. It is installed with priority 20 so it's likely going to be selected first.
