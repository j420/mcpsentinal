# True positive: PyJWT decode with verify=False — no signature check.
import jwt


def authorize(token: str, key: str) -> dict:
    claims = jwt.decode(token, key, verify=False)
    return claims
