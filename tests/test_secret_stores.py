"""Tests for the Azure Key Vault and AWS Secrets Manager credential providers (#3, #4).

Both providers share one fixture pattern: a fake :class:`SecretStore` (or a
fake SDK client behind the real store class) holding a freshly generated
self-signed certificate. No cloud SDK or network access is needed.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

import msal
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from mcp_defender_xdr.auth import (
    AzureCredentials,
    JsonFileCredentialProvider,
    TokenManager,
    _build_client_credential,
)
from mcp_defender_xdr.errors import AuthError
from mcp_defender_xdr.secret_stores import (
    PROVIDER_AWS,
    PROVIDER_KEYVAULT,
    AwsSecretsManagerSecretStore,
    CertificateMaterial,
    KeyVaultSecretStore,
    SecretStore,
    decode_certificate_material,
)

TENANT_ID = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"
VAULT = "https://kv-fixture.vault.azure.net/"
REGION = "us-east-1"
ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:defender/contoso-AbCdEf"


# ---------- shared certificate fixture ----------


class Cert:
    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mcp-defender-xdr-test")])
        now = dt.datetime.now(dt.UTC)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .sign(self.key, hashes.SHA256())
        )

    def pfx(self, passphrase: str | None = None) -> bytes:
        encryption = (
            serialization.BestAvailableEncryption(passphrase.encode())
            if passphrase
            else serialization.NoEncryption()
        )
        return pkcs12.serialize_key_and_certificates(b"t", self.key, self.cert, None, encryption)

    def pem(self, passphrase: str | None = None) -> str:
        encryption = (
            serialization.BestAvailableEncryption(passphrase.encode())
            if passphrase
            else serialization.NoEncryption()
        )
        key = self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
        ).decode()
        return key + self.cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture(scope="module")
def cert() -> Cert:
    return Cert()


class FakeStore(SecretStore):
    def __init__(self, secrets: dict[str, bytes | str], *, error: Exception | None = None) -> None:
        self.location = "fake store"
        self.secrets = secrets
        self.error = error
        self.reads: list[tuple[str, str | None]] = []

    def get(self, name: str, version: str | None = None) -> bytes | str:
        self.reads.append((name, version))
        if self.error is not None:
            from mcp_defender_xdr.secret_stores import _classify

            raise _classify(self.error) from self.error
        if name not in self.secrets:
            from mcp_defender_xdr.secret_stores import SecretNotFound

            raise SecretNotFound(name)
        return self.secrets[name]


def _factories(store: SecretStore) -> dict[str, Any]:
    return {PROVIDER_KEYVAULT: lambda entry: store, PROVIDER_AWS: lambda entry: store}


def _tenants_file(tmp_path: Path, tenants: dict[str, Any]) -> Path:
    path = tmp_path / "tenants.json"
    path.write_text(json.dumps({"default": next(iter(tenants)), "tenants": tenants}))
    os.chmod(path, 0o600)
    return path


def _kv_entry(**extra: Any) -> dict[str, Any]:
    return {
        "provider": "keyvault",
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "vault_url": VAULT,
        "cert_secret_name": "contoso-defender-cert",
        **extra,
    }


def _aws_entry(**extra: Any) -> dict[str, Any]:
    return {
        "provider": "aws-secretsmanager",
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "region": REGION,
        "secret_id": ARN,
        **extra,
    }


# ---------- decoding ----------


def test_decode_raw_pfx_bytes(cert: Cert) -> None:
    material = decode_certificate_material(cert.pfx(), passphrase=None, source="t")
    assert material.certificate_pem == cert.cert_pem
    assert "BEGIN PRIVATE KEY" in material.private_key_pem


def test_decode_base64_pfx_with_passphrase(cert: Cert) -> None:
    encoded = base64.b64encode(cert.pfx("s3cret")).decode()
    wrapped = "\n".join(encoded[i : i + 64] for i in range(0, len(encoded), 64))
    material = decode_certificate_material(wrapped, passphrase="s3cret", source="t")
    assert material.certificate_pem == cert.cert_pem


@pytest.mark.parametrize("passphrase", [None, "pem-pass"])
def test_decode_pem_bundle(cert: Cert, passphrase: str | None) -> None:
    material = decode_certificate_material(cert.pem(passphrase), passphrase=passphrase, source="t")
    assert material.certificate_pem == cert.cert_pem
    assert "ENCRYPTED" not in material.private_key_pem


def test_decode_wrong_passphrase(cert: Cert) -> None:
    with pytest.raises(AuthError, match="passphrase is wrong"):
        decode_certificate_material(cert.pfx("right"), passphrase="wrong", source="t")


@pytest.mark.parametrize(
    "raw",
    ["not base64 !!", base64.b64encode(b"not a pfx").decode(), b"\x00\x01garbage"],
)
def test_decode_garbage(raw: bytes | str) -> None:
    with pytest.raises(AuthError):
        decode_certificate_material(raw, passphrase=None, source="t")


def test_decode_pem_without_key(cert: Cert) -> None:
    with pytest.raises(AuthError, match="must contain a private key"):
        decode_certificate_material(cert.cert_pem, passphrase=None, source="t")


def test_decode_pfx_without_key(cert: Cert) -> None:
    cert_only = pkcs12.serialize_key_and_certificates(
        b"t", None, None, [cert.cert], serialization.NoEncryption()
    )
    with pytest.raises(AuthError, match="must contain a private key"):
        decode_certificate_material(cert_only, passphrase=None, source="t")


def test_material_repr_redacts_key(cert: Cert) -> None:
    material = decode_certificate_material(cert.pfx(), passphrase=None, source="t")
    assert "PRIVATE KEY" not in repr(material)
    creds = AzureCredentials(tenant_id=TENANT_ID, client_id=CLIENT_ID, certificate=material)
    assert "PRIVATE KEY" not in repr(creds)
    assert "IN-MEMORY" in repr(creds)


def test_azure_credentials_needs_exactly_one_cert_source(cert: Cert) -> None:
    material = decode_certificate_material(cert.pfx(), passphrase=None, source="t")
    with pytest.raises(ValueError):
        AzureCredentials(tenant_id=TENANT_ID, client_id=CLIENT_ID)
    with pytest.raises(ValueError):
        AzureCredentials(
            tenant_id=TENANT_ID, client_id=CLIENT_ID, cert_path="/x.pfx", certificate=material
        )


# ---------- providers: happy path (shared across both) ----------


@pytest.mark.parametrize(
    ("entry", "secret_name", "value_kind"),
    [
        (_kv_entry(), "contoso-defender-cert", "base64"),
        (_kv_entry(cert_secret_version="0" * 32), "contoso-defender-cert", "pem"),
        (_aws_entry(), ARN, "binary"),
        (_aws_entry(secret_id="defender/contoso"), "defender/contoso", "base64"),
    ],
)
def test_provider_loads_certificate_without_touching_disk(
    tmp_path: Path, cert: Cert, entry: dict[str, Any], secret_name: str, value_kind: str
) -> None:
    values: dict[str, bytes | str] = {
        "base64": base64.b64encode(cert.pfx()).decode(),
        "pem": cert.pem(),
        "binary": cert.pfx(),
    }
    value = values[value_kind]
    store = FakeStore({secret_name: value})
    path = _tenants_file(tmp_path, {"contoso": entry})
    before = set(tmp_path.iterdir())

    provider = JsonFileCredentialProvider(path, env={}, store_factories=_factories(store))

    creds = provider.get_credentials("contoso")
    assert creds.cert_path is None
    assert creds.certificate is not None
    assert creds.certificate.certificate_pem == cert.cert_pem
    assert set(tmp_path.iterdir()) == before  # nothing written next to the config
    assert store.reads[0] == (secret_name, entry.get("cert_secret_version"))
    credential = _build_client_credential(creds)
    assert set(credential) == {"private_key", "public_certificate"}


@pytest.mark.parametrize("make_entry", [_kv_entry, _aws_entry])
def test_provider_passphrase_from_secret(tmp_path: Path, cert: Cert, make_entry: Any) -> None:
    key = "passphrase_secret_name" if make_entry is _kv_entry else "passphrase_secret_id"
    entry = make_entry(**{key: "cert-pass"})
    cert_name = entry.get("cert_secret_name") or entry["secret_id"]
    store = FakeStore({cert_name: cert.pfx("pw-123"), "cert-pass": "pw-123"})
    provider = JsonFileCredentialProvider(
        _tenants_file(tmp_path, {"contoso": entry}), env={}, store_factories=_factories(store)
    )
    assert provider.get_credentials().certificate is not None


@pytest.mark.parametrize("make_entry", [_kv_entry, _aws_entry])
def test_provider_passphrase_from_env(tmp_path: Path, cert: Cert, make_entry: Any) -> None:
    entry = make_entry(cert_passphrase_env="CONTOSO_PASS")
    cert_name = entry.get("cert_secret_name") or entry["secret_id"]
    store = FakeStore({cert_name: cert.pfx("env-pw")})
    path = _tenants_file(tmp_path, {"contoso": entry})
    provider = JsonFileCredentialProvider(
        path, env={"CONTOSO_PASS": "env-pw"}, store_factories=_factories(store)
    )
    assert provider.get_credentials().certificate is not None
    with pytest.raises(AuthError, match="is not set"):
        JsonFileCredentialProvider(path, env={}, store_factories=_factories(store))


def test_mixed_file_and_remote_tenants(tmp_path: Path, cert: Cert) -> None:
    pfx = tmp_path / "fabrikam.pfx"
    pfx.write_bytes(cert.pfx())
    store = FakeStore({"contoso-defender-cert": cert.pem()})
    path = _tenants_file(
        tmp_path,
        {
            "contoso": _kv_entry(),
            "fabrikam": {"tenant_id": TENANT_ID, "client_id": CLIENT_ID, "cert_path": str(pfx)},
        },
    )
    provider = JsonFileCredentialProvider(path, env={}, store_factories=_factories(store))
    assert provider.list_tenants() == ["contoso", "fabrikam"]
    assert provider.get_credentials("fabrikam").cert_path == str(pfx)
    assert provider.get_credentials("contoso").certificate is not None


# ---------- providers: missing secret and auth failure ----------


class ResourceNotFoundError(Exception):  # shaped like azure.core.exceptions
    status_code = 404


class ClientAuthenticationError(Exception):
    status_code = 401


class CredentialUnavailableError(Exception):
    pass


class ClientError(Exception):  # shaped like botocore.exceptions.ClientError
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code, "Message": "..."}}


class NoCredentialsError(Exception):
    pass


@pytest.mark.parametrize(
    ("make_entry", "error"),
    [
        (_kv_entry, ResourceNotFoundError("gone")),
        (_aws_entry, ClientError("ResourceNotFoundException")),
    ],
)
def test_provider_missing_secret(tmp_path: Path, make_entry: Any, error: Exception) -> None:
    store = FakeStore({}, error=error)
    with pytest.raises(AuthError, match="Secret not found") as excinfo:
        JsonFileCredentialProvider(
            _tenants_file(tmp_path, {"contoso": make_entry()}),
            env={},
            store_factories=_factories(store),
        )
    assert "contoso" in str(excinfo.value)


def test_provider_missing_secret_without_sdk_error(tmp_path: Path) -> None:
    with pytest.raises(AuthError, match="Secret not found"):
        JsonFileCredentialProvider(
            _tenants_file(tmp_path, {"contoso": _kv_entry()}),
            env={},
            store_factories=_factories(FakeStore({})),
        )


@pytest.mark.parametrize(
    ("make_entry", "error"),
    [
        (_kv_entry, ClientAuthenticationError("bad")),
        (_kv_entry, CredentialUnavailableError("no identity")),
        (_aws_entry, ClientError("AccessDeniedException")),
        (_aws_entry, NoCredentialsError()),
    ],
)
def test_provider_auth_failure(tmp_path: Path, make_entry: Any, error: Exception) -> None:
    store = FakeStore({}, error=error)
    with pytest.raises(AuthError, match="Access denied or no cloud identity"):
        JsonFileCredentialProvider(
            _tenants_file(tmp_path, {"contoso": make_entry()}),
            env={},
            store_factories=_factories(store),
        )


def test_provider_unexpected_store_error_is_wrapped(tmp_path: Path) -> None:
    store = FakeStore({}, error=RuntimeError("socket closed"))
    with pytest.raises(AuthError, match=r"Failed to read .*RuntimeError"):
        JsonFileCredentialProvider(
            _tenants_file(tmp_path, {"contoso": _aws_entry()}),
            env={},
            store_factories=_factories(store),
        )


# ---------- providers: config validation ----------


@pytest.mark.parametrize(
    "entry",
    [
        _kv_entry(vault_url="http://kv-fixture.vault.azure.net"),
        _kv_entry(vault_url="https://evil.example.com"),
        _kv_entry(cert_secret_name="has spaces"),
        _kv_entry(cert_secret_version="latest"),
        _kv_entry(keyvault_identity_client_id="not-a-guid"),
        _kv_entry(cert_path="/x.pfx"),
        _kv_entry(cert_passphrase="inline"),
        _kv_entry(passphrase_secret_name="p", cert_passphrase_env="P"),
        _aws_entry(region="mars"),
        _aws_entry(secret_id=""),
        {**_aws_entry(), "provider": "gcp-secret-manager"},
        {"provider": "keyvault", "vault_url": VAULT, "cert_secret_name": "c"},
    ],
)
def test_provider_rejects_bad_config(tmp_path: Path, cert: Cert, entry: dict[str, Any]) -> None:
    store = FakeStore({"c": cert.pfx(), "contoso-defender-cert": cert.pfx(), ARN: cert.pfx()})
    with pytest.raises(AuthError):
        JsonFileCredentialProvider(
            _tenants_file(tmp_path, {"contoso": entry}),
            env={"P": "x"},
            store_factories=_factories(store),
        )


# ---------- the real store classes, against fake SDK clients ----------


class FakeKeyVaultClient:
    def __init__(self, value: str | None = None, error: Exception | None = None) -> None:
        self.value = value
        self.error = error
        self.calls: list[tuple[str, str | None]] = []

    def get_secret(self, name: str, version: str | None = None) -> Any:
        self.calls.append((name, version))
        if self.error:
            raise self.error
        return type("KeyVaultSecret", (), {"value": self.value})()


def test_keyvault_store_reads_secret_and_passes_identity() -> None:
    seen: dict[str, Any] = {}
    client = FakeKeyVaultClient("abc")

    def factory(vault_url: str, identity: str | None) -> FakeKeyVaultClient:
        seen.update(vault_url=vault_url, identity=identity)
        return client

    store = KeyVaultSecretStore(VAULT, identity_client_id="mi-id", client_factory=factory)
    assert store.get("name", "v1") == "abc"
    assert client.calls == [("name", "v1")]
    assert seen == {"vault_url": VAULT, "identity": "mi-id"}
    assert VAULT in store.location


@pytest.mark.parametrize(
    ("client", "expected"),
    [
        (FakeKeyVaultClient(error=ResourceNotFoundError()), "SecretNotFound"),
        (FakeKeyVaultClient(error=ClientAuthenticationError()), "SecretAccessDenied"),
        (FakeKeyVaultClient(value=""), "SecretNotFound"),
    ],
)
def test_keyvault_store_maps_errors(client: FakeKeyVaultClient, expected: str) -> None:
    store = KeyVaultSecretStore(VAULT, client_factory=lambda *_: client)
    with pytest.raises(Exception) as excinfo:
        store.get("name")
    assert type(excinfo.value).__name__ == expected


class FakeSecretsManagerClient:
    def __init__(self, response: dict[str, Any] | None = None, error: Exception | None = None):
        self.response = response or {}
        self.error = error

    def get_secret_value(self, SecretId: str) -> dict[str, Any]:
        if self.error:
            raise self.error
        return self.response


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ({"SecretBinary": b"\x01\x02"}, b"\x01\x02"),
        ({"SecretString": "text"}, "text"),
        ({"SecretBinary": b"", "SecretString": "fallback"}, "fallback"),
    ],
)
def test_aws_store_reads_binary_or_string(response: dict[str, Any], expected: bytes | str) -> None:
    store = AwsSecretsManagerSecretStore(
        REGION, client_factory=lambda _: FakeSecretsManagerClient(response)
    )
    assert store.get(ARN) == expected
    assert REGION in store.location


@pytest.mark.parametrize(
    ("client", "expected"),
    [
        (
            FakeSecretsManagerClient(error=ClientError("ResourceNotFoundException")),
            "SecretNotFound",
        ),
        (
            FakeSecretsManagerClient(error=ClientError("AccessDeniedException")),
            "SecretAccessDenied",
        ),
        (FakeSecretsManagerClient(error=NoCredentialsError()), "SecretAccessDenied"),
        (FakeSecretsManagerClient({}), "SecretNotFound"),
        (FakeSecretsManagerClient(error=ClientError("ThrottlingException")), "ClientError"),
    ],
)
def test_aws_store_maps_errors(client: FakeSecretsManagerClient, expected: str) -> None:
    store = AwsSecretsManagerSecretStore(REGION, client_factory=lambda _: client)
    with pytest.raises(Exception) as excinfo:
        store.get(ARN)
    assert type(excinfo.value).__name__ == expected


# ---------- MSAL really signs with the in-memory key ----------


class _Resp:
    def __init__(self, body: dict[str, Any]) -> None:
        self.status_code = 200
        self.text = json.dumps(body)
        self.headers: dict[str, str] = {}

    def raise_for_status(self) -> None:
        return None


class _FakeAadHttp:
    def __init__(self) -> None:
        self.token_requests: list[dict[str, Any]] = []

    def get(self, url: str, **_: Any) -> _Resp:
        base = f"https://login.microsoftonline.com/{TENANT_ID}"
        return _Resp(
            {
                "authorization_endpoint": f"{base}/oauth2/v2.0/authorize",
                "token_endpoint": f"{base}/oauth2/v2.0/token",
                "issuer": f"{base}/v2.0",
            }
        )

    def post(self, url: str, data: dict[str, Any] | None = None, **_: Any) -> _Resp:
        self.token_requests.append(dict(data or {}))
        return _Resp({"access_token": "aad-token", "expires_in": 3600, "token_type": "Bearer"})


def _b64url(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def test_token_manager_signs_client_assertion_with_in_memory_key(cert: Cert) -> None:
    material = decode_certificate_material(cert.pfx(), passphrase=None, source="t")
    http = _FakeAadHttp()

    class Provider(JsonFileCredentialProvider):
        def __init__(self) -> None:
            self._default_tenant = "contoso"
            self._tenants = {
                "contoso": AzureCredentials(
                    tenant_id=TENANT_ID, client_id=CLIENT_ID, certificate=material
                )
            }

    def factory(**kwargs: Any) -> msal.ConfidentialClientApplication:
        return msal.ConfidentialClientApplication(
            **kwargs, http_client=http, instance_discovery=False
        )

    manager = TokenManager(Provider(), msal_factory=factory)
    assert manager.get_token() == "aad-token"

    assertion = http.token_requests[0]["client_assertion"]
    assertion = assertion.decode() if isinstance(assertion, bytes) else assertion
    header_b64, payload_b64, signature_b64 = assertion.split(".")
    header = json.loads(_b64url(header_b64))
    assert header["alg"] == "PS256"
    assert header["x5t#S256"]
    payload = json.loads(_b64url(payload_b64))
    assert payload["iss"] == CLIENT_ID
    cert.key.public_key().verify(
        _b64url(signature_b64),
        f"{header_b64}.{payload_b64}".encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256.digest_size),
        hashes.SHA256(),
    )


def test_certificate_material_msal_credential_shape(cert: Cert) -> None:
    material = CertificateMaterial(private_key_pem="k", certificate_pem="c")
    assert material.msal_credential() == {"private_key": "k", "public_certificate": "c"}
