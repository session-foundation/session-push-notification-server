from session_util.onionreq import OnionReqParser


def decrypt(data: bytes, keys) -> tuple[OnionReqParser, str]:
    """
    Decrypts the onion request `data` with the first of `keys` that can: a list of (key name,
    X25519 pubkey bytes, X25519 privkey bytes), as conf.ONIONREQ_KEYS.  Returns the parser and the
    name of the key that decrypted it.  Raises ValueError if none can.
    """
    error = None
    for name, pubkey, privkey in keys:
        try:
            return OnionReqParser(pubkey, privkey, data), name
        except Exception as e:
            error = e
    raise ValueError(f"no key could decrypt it (tried {len(keys)}; last error: {error})")
