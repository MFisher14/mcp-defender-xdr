#!/usr/bin/env python3
"""Mint a short-lived bearer token for mcp-defender-xdr's HTTP transport.

The server only *validates* tokens; issuing them is the operator's job. In
production that is usually your identity provider or an internal token
service. This script is the minimal stand-in for development and for
understanding exactly what the server checks.

HS256 (shared secret, same value the server has in MCP_DEFENDER_XDR_JWT_SECRET)::

    MCP_DEFENDER_XDR_JWT_SECRET=... python examples/mint_token.py \\
        --audience mcp-defender-xdr://soc-prod --issuer https://tokens.example.com \\
        --subject analyst@example.com

RS256 / ES256 (the server holds only the public key)::

    python examples/mint_token.py --algorithm ES256 --private-key signer.pem \\
        --audience mcp-defender-xdr://soc-prod --issuer https://tokens.example.com \\
        --subject analyst@example.com

Each token carries a fresh random ``jti`` and lives 15 minutes by default. It
may open **one** MCP session; mint a new one to reconnect.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import time
from pathlib import Path

import jwt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--audience", required=True, help="Must equal MCP_DEFENDER_XDR_JWT_AUDIENCE"
    )
    parser.add_argument("--issuer", required=True, help="Must equal MCP_DEFENDER_XDR_JWT_ISSUER")
    parser.add_argument("--subject", required=True, help="Who the token is for (audited)")
    parser.add_argument("--algorithm", default="HS256")
    parser.add_argument("--ttl", type=int, default=900, help="Lifetime in seconds (default 900)")
    parser.add_argument(
        "--private-key", type=Path, help="PEM private key for asymmetric algorithms"
    )
    args = parser.parse_args()

    if args.algorithm.startswith("HS"):
        key: str | bytes = os.environ.get("MCP_DEFENDER_XDR_JWT_SECRET", "")
        if not key:
            print("Set MCP_DEFENDER_XDR_JWT_SECRET to the server's shared secret.", file=sys.stderr)
            return 2
    else:
        if args.private_key is None:
            print(f"--private-key is required for {args.algorithm}.", file=sys.stderr)
            return 2
        key = args.private_key.read_bytes()

    now = int(time.time())
    claims = {
        "iss": args.issuer,
        "aud": args.audience,
        "sub": args.subject,
        "iat": now,
        "nbf": now,
        "exp": now + args.ttl,
        "jti": secrets.token_urlsafe(16),
    }
    print(jwt.encode(claims, key, algorithm=args.algorithm))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
