# Same as spns.conf except that it loads a config on initialization (available as config).

from .conf import logger, PRIVKEYS, PUBKEYS, ONIONREQ_KEYS, NOTIFY, load_config

config = load_config()
