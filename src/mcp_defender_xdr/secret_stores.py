"""Credential providers backed by a cloud secret manager.

The file-based providers in :mod:`.auth` need the PFX bundle on the host's
filesystem. These providers fetch it at startup from **Azure Key Vault** or
**AWS Secrets Manager** instead, parse it in memory, and hand MSAL the PEM
key and certificate directly, so the PFX never touches disk. See THREAT_MODEL.md, T2.

The cloud SDKs are optional extras, imported only when a provider is used::

    pip install 'mcp-defender-xdr[keyvault]'            # azure-identity + azure-keyvault-secrets
    pip install 'mcp-defender-xdr[aws-secretsmanager]'  # boto3

Both providers share :class:`RemoteSecretCredentialProvider`, which owns
fetching, decoding, and error mapping; a store only knows how to read one
named secret. Tests drive the providers with fake stores, so no SDK is
needed to run them.
"""

from __future__ import annotations

import base64
import binascii
import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from .audit import audit
from .errors import AuthError

PROVIDER_FILE = "file"
PROVIDER_KEYVAULT = "keyvault"
PROVIDER_AWS = "aws-secretsmanager"
REMOTE_PROVIDERS = (PROVIDER_KEYVAULT, PROVIDER_AWS)

_VAULT_URL_RE = re.compile(r"^https://[A-Za-z0-9-]{3,24}\.vault\.[A-Za-z0-9.-]+/?$")
_KV_SECRET_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,127}$")
_KV_VERSION_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_AWS_SECRET_ID_RE = re.compile(
    r"^(arn:aws[a-z-]*:secretsmanager:[A-Za-z0-9:/_+=.@-]+|[A-Za-z0-9/_+=.@-]{1,512})$"
)
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_AWS_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d{1,2}$")


# ---------- certificate material ----------


@dataclass(frozen=True)
class CertificateMaterial:
    """An unencrypted PEM private key and its public certificate, held in memory only."""

    private_key_pem: str
    certificate_pem: str

    def __repr__(self) -> str:
        return "CertificateMaterial(private_key_pem='***REDACTED***', certificate_pem=...)"

    def msal_credential(self) -> dict[str, Any]:
        # With a PEM `public_certificate` and no `thumbprint`, MSAL (>=1.35)
        # computes the SHA-256 thumbprint and signs with PS256, the same as it
        # does for a `.pfx` path.
        return {"private_key": self.private_key_pem, "public_certificate": self.certificate_pem}


def decode_certificate_material(
    raw: bytes | str, *, passphrase: str | None, source: str
) -> CertificateMaterial:
    """Turn a secret value into :class:`CertificateMaterial`.

    Accepts the formats a secret manager typically holds:

    * raw PKCS#12 bytes (AWS ``SecretBinary``);
    * base64-encoded PKCS#12 (a Key Vault certificate's backing secret, or a
      string secret someone uploaded);
    * PEM text containing both a private key and a certificate (Key Vault
      certificates created with content type ``application/x-pem-file``).

    The error messages name ``source`` but never include secret content.
    """
    text = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else raw
    if "-----BEGIN" in text:
        return _from_pem(text, passphrase=passphrase, source=source)
    if isinstance(raw, str):
        try:
            data = base64.b64decode("".join(raw.split()), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AuthError(
                f"Certificate secret is neither PEM nor base64-encoded PKCS#12 ({source})"
            ) from exc
    else:
        data = raw
    return _from_pkcs12(data, passphrase=passphrase, source=source)


def _from_pkcs12(data: bytes, *, passphrase: str | None, source: str) -> CertificateMaterial:
    password = passphrase.encode("utf-8") if passphrase else None
    try:
        key, cert, _ = pkcs12.load_key_and_certificates(data, password)
    except (ValueError, TypeError) as exc:
        raise AuthError(
            f"Certificate secret is not a valid PKCS#12 bundle, or the passphrase is wrong ({source})"
        ) from exc
    if key is None or cert is None:
        raise AuthError(f"PKCS#12 bundle must contain a private key and a certificate ({source})")
    return CertificateMaterial(
        private_key_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii"),
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    )


_PEM_KEY_RE = re.compile(
    r"-----BEGIN (?:ENCRYPTED |RSA |EC )?PRIVATE KEY-----.+?-----END (?:ENCRYPTED |RSA |EC )?PRIVATE KEY-----",
    re.DOTALL,
)
_PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)


def _from_pem(text: str, *, passphrase: str | None, source: str) -> CertificateMaterial:
    key_match = _PEM_KEY_RE.search(text)
    cert_match = _PEM_CERT_RE.search(text)
    if key_match is None or cert_match is None:
        raise AuthError(f"PEM secret must contain a private key and a certificate ({source})")
    password = passphrase.encode("utf-8") if passphrase else None
    try:
        key = serialization.load_pem_private_key(key_match.group(0).encode("ascii"), password)
        cert = x509.load_pem_x509_certificate(cert_match.group(0).encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise AuthError(
            f"PEM secret could not be parsed, or the passphrase is wrong ({source})"
        ) from exc
    return CertificateMaterial(
        private_key_pem=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii"),
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    )


# ---------- secret stores ----------


class SecretNotFound(Exception):
    """The named secret does not exist (or the caller may not know that it does)."""


class SecretAccessDenied(Exception):
    """The store rejected our identity, or no identity could be found."""


class SecretStore(ABC):
    """Reads one named secret. Implementations translate SDK errors into the two above."""

    #: Human-readable location for error messages and audit records.
    location: str

    @abstractmethod
    def get(self, name: str, version: str | None = None) -> bytes | str: ...


def _missing_extra(extra: str, package: str) -> AuthError:
    return AuthError(
        f"The '{package}' package is required for this credential provider. "
        f"Install it with: pip install 'mcp-defender-xdr[{extra}]'"
    )


class KeyVaultSecretStore(SecretStore):
    """Azure Key Vault secrets, authenticated with ``DefaultAzureCredential``.

    ``DefaultAzureCredential`` tries, in order, environment-variable service
    principal (``AZURE_CLIENT_ID``/``AZURE_TENANT_ID``/``AZURE_CLIENT_SECRET``
    or ``AZURE_CLIENT_CERTIFICATE_PATH``), workload identity, managed identity,
    and developer sign-ins (Azure CLI and so on). That covers AKS, App Service,
    VMs, and a laptop with no code change. Interactive browser sign-in stays off.

    ``identity_client_id`` pins the user-assigned managed identity / workload
    identity to use. Without it, ``DefaultAzureCredential`` falls back to the
    ``AZURE_CLIENT_ID`` environment variable, which is easy to confuse with
    the Defender App Registration's client ID.
    """

    def __init__(
        self,
        vault_url: str,
        *,
        identity_client_id: str | None = None,
        client_factory: Callable[[str, str | None], Any] | None = None,
    ) -> None:
        self.location = f"Key Vault {vault_url}"
        factory = client_factory or self._default_client
        self._client = factory(vault_url, identity_client_id)

    @staticmethod
    def _default_client(vault_url: str, identity_client_id: str | None) -> Any:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except ImportError as exc:  # pragma: no cover - depends on installed extras
            raise _missing_extra("keyvault", "azure-keyvault-secrets") from exc
        kwargs: dict[str, str] = {}
        if identity_client_id:
            kwargs = {
                "managed_identity_client_id": identity_client_id,
                "workload_identity_client_id": identity_client_id,
            }
        return SecretClient(vault_url=vault_url, credential=DefaultAzureCredential(**kwargs))

    def get(self, name: str, version: str | None = None) -> bytes | str:
        try:
            secret = self._client.get_secret(name, version)
        except Exception as exc:
            raise _classify(exc) from exc
        value = getattr(secret, "value", None)
        if not isinstance(value, str) or not value:
            raise SecretNotFound(name)
        return value


class AwsSecretsManagerSecretStore(SecretStore):
    """AWS Secrets Manager, authenticated with the standard AWS credential chain.

    boto3's default chain covers environment variables, shared config and SSO
    profiles, IRSA / EKS Pod Identity web-identity tokens, ECS task roles, and
    EC2 instance profiles.
    """

    def __init__(
        self,
        region: str,
        *,
        client_factory: Callable[[str], Any] | None = None,
    ) -> None:
        self.location = f"AWS Secrets Manager ({region})"
        factory = client_factory or self._default_client
        self._client = factory(region)

    @staticmethod
    def _default_client(region: str) -> Any:
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - depends on installed extras
            raise _missing_extra("aws-secretsmanager", "boto3") from exc
        return boto3.client("secretsmanager", region_name=region)

    def get(self, name: str, version: str | None = None) -> bytes | str:
        # Secrets Manager versions are addressed by stage; AWSCURRENT is the default.
        del version
        try:
            response = self._client.get_secret_value(SecretId=name)
        except Exception as exc:
            raise _classify(exc) from exc
        binary = response.get("SecretBinary")
        if isinstance(binary, bytes | bytearray) and binary:
            return bytes(binary)
        string = response.get("SecretString")
        if isinstance(string, str) and string:
            return string
        raise SecretNotFound(name)


_NOT_FOUND_NAMES = frozenset({"ResourceNotFoundError", "ResourceNotFoundException"})
_DENIED_NAMES = frozenset(
    {
        "ClientAuthenticationError",
        "CredentialUnavailableError",
        "NoCredentialsError",
        "PartialCredentialsError",
        "AccessDeniedException",
        "UnrecognizedClientException",
        "ExpiredTokenException",
        "InvalidSignatureException",
    }
)


def _classify(exc: Exception) -> Exception:
    """Map Azure / AWS SDK errors without importing either SDK.

    Azure raises typed exceptions carrying ``status_code``; botocore raises
    ``ClientError`` carrying ``response["Error"]["Code"]``. Both are read
    structurally so this module imports cleanly when neither SDK is installed.
    """
    names = {type(exc).__name__}
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping) and isinstance(error.get("Code"), str):
            names.add(error["Code"])
    status = getattr(exc, "status_code", None)
    if names & _NOT_FOUND_NAMES or status == 404:
        return SecretNotFound()
    if names & _DENIED_NAMES or status in (401, 403):
        return SecretAccessDenied(type(exc).__name__)
    return exc


# ---------- credential providers ----------


@dataclass(frozen=True)
class SecretRef:
    """Names a secret inside a store; ``version`` is honoured by Key Vault only."""

    name: str
    version: str | None = None


class RemoteSecretCredentialProvider:
    """Shared fetch/decode logic for one tenant whose certificate lives in a secret store.

    Not a :class:`~.auth.CredentialProvider` itself: :func:`load_remote_credentials`
    returns ``AzureCredentials`` that the single-tenant and tenants-file
    providers in :mod:`.auth` serve unchanged.
    """

    provider_name: str = "remote"

    def __init__(
        self,
        store: SecretStore,
        *,
        tenant_key: str,
        certificate: SecretRef,
        passphrase_secret: SecretRef | None = None,
        passphrase: str | None = None,
    ) -> None:
        if passphrase_secret is not None and passphrase is not None:
            raise AuthError(
                f"Tenant '{tenant_key}' sets a passphrase secret and a passphrase "
                "environment variable; choose one."
            )
        self._store = store
        self._tenant_key = tenant_key
        self._certificate = certificate
        self._passphrase_secret = passphrase_secret
        self._passphrase = passphrase

    def _read(self, ref: SecretRef, *, what: str) -> bytes | str:
        where = f"{what} '{ref.name}' in {self._store.location} (tenant '{self._tenant_key}')"
        try:
            return self._store.get(ref.name, ref.version)
        except SecretNotFound as exc:
            raise AuthError(f"Secret not found: {where}") from exc
        except SecretAccessDenied as exc:
            raise AuthError(
                f"Access denied or no cloud identity available reading {where}: {exc}"
            ) from exc
        except AuthError:
            raise
        except Exception as exc:
            raise AuthError(f"Failed to read {where}: {type(exc).__name__}") from exc

    def load(self) -> CertificateMaterial:
        passphrase = self._passphrase
        if self._passphrase_secret is not None:
            raw = self._read(self._passphrase_secret, what="passphrase secret")
            passphrase = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        raw_cert = self._read(self._certificate, what="certificate secret")
        material = decode_certificate_material(
            raw_cert,
            passphrase=passphrase,
            source=f"{self._store.location}, tenant '{self._tenant_key}'",
        )
        audit(
            "credential-loaded-from-secret-store",
            tenant=self._tenant_key,
            provider=self.provider_name,
            store=self._store.location,
            secret=self._certificate.name,
        )
        return material


class KeyVaultCredentialProvider(RemoteSecretCredentialProvider):
    provider_name = PROVIDER_KEYVAULT


class AwsSecretsManagerCredentialProvider(RemoteSecretCredentialProvider):
    provider_name = PROVIDER_AWS


#: Factories that tests replace to inject fake stores.
StoreFactories = Mapping[str, Callable[[Mapping[str, Any]], SecretStore]]


def _default_store_factories() -> dict[str, Callable[[Mapping[str, Any]], SecretStore]]:
    return {
        PROVIDER_KEYVAULT: lambda entry: KeyVaultSecretStore(
            str(entry["vault_url"]),
            identity_client_id=entry.get("keyvault_identity_client_id"),
        ),
        PROVIDER_AWS: lambda entry: AwsSecretsManagerSecretStore(str(entry["region"])),
    }


def _require_str(entry: Mapping[str, Any], name: str, where: str, pattern: re.Pattern[str]) -> str:
    value = entry.get(name)
    if not isinstance(value, str) or not pattern.match(value):
        raise AuthError(f"{where}: '{name}' is missing or malformed")
    return value


def _optional_str(
    entry: Mapping[str, Any], name: str, where: str, pattern: re.Pattern[str]
) -> str | None:
    if entry.get(name) is None:
        return None
    return _require_str(entry, name, where, pattern)


def load_remote_credentials(
    provider: str,
    tenant_key: str,
    entry: Mapping[str, Any],
    *,
    env: Mapping[str, str],
    store_factories: StoreFactories | None = None,
) -> CertificateMaterial:
    """Validate a ``provider: keyvault | aws-secretsmanager`` entry and fetch its certificate.

    ``entry`` uses the tenants-file field names; single-tenant env mode maps
    its variables onto the same names before calling this.
    """
    where = f"Tenant '{tenant_key}' ({provider})"
    passphrase_env = entry.get("cert_passphrase_env")
    passphrase: str | None = None
    if passphrase_env is not None:
        if not isinstance(passphrase_env, str) or not passphrase_env:
            raise AuthError(f"{where}: 'cert_passphrase_env' must be a non-empty string")
        passphrase = env.get(passphrase_env)
        if not passphrase:
            raise AuthError(
                f"{where}: cert_passphrase_env '{passphrase_env}' is not set in the environment"
            )
    if entry.get("cert_passphrase") is not None or entry.get("cert_path") is not None:
        raise AuthError(
            f"{where}: 'cert_path' and inline 'cert_passphrase' do not apply to secret-store "
            "providers; the certificate is read from the store."
        )

    factories = dict(store_factories or _default_store_factories())
    if provider == PROVIDER_KEYVAULT:
        _require_str(entry, "vault_url", where, _VAULT_URL_RE)
        _optional_str(entry, "keyvault_identity_client_id", where, _GUID_RE)
        cert = SecretRef(
            _require_str(entry, "cert_secret_name", where, _KV_SECRET_NAME_RE),
            _optional_str(entry, "cert_secret_version", where, _KV_VERSION_RE),
        )
        pass_name = _optional_str(entry, "passphrase_secret_name", where, _KV_SECRET_NAME_RE)
        return KeyVaultCredentialProvider(
            factories[provider](entry),
            tenant_key=tenant_key,
            certificate=cert,
            passphrase_secret=SecretRef(pass_name) if pass_name else None,
            passphrase=passphrase,
        ).load()
    if provider == PROVIDER_AWS:
        _require_str(entry, "region", where, _AWS_REGION_RE)
        cert = SecretRef(_require_str(entry, "secret_id", where, _AWS_SECRET_ID_RE))
        pass_id = _optional_str(entry, "passphrase_secret_id", where, _AWS_SECRET_ID_RE)
        return AwsSecretsManagerCredentialProvider(
            factories[provider](entry),
            tenant_key=tenant_key,
            certificate=cert,
            passphrase_secret=SecretRef(pass_id) if pass_id else None,
            passphrase=passphrase,
        ).load()
    raise AuthError(
        f"Tenant '{tenant_key}': unknown provider '{provider}' "
        f"(expected one of: {PROVIDER_FILE}, {', '.join(REMOTE_PROVIDERS)})"
    )
