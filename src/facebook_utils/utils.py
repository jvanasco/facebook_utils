import os
import re
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
import warnings


# ==============================================================================


RE_api_version_fixable = re.compile(r"\d+\.\d+")
RE_api_version_valid = re.compile(r"v\d+\.\d+")


def warn_future(message: str):
    warnings.warn(message, FutureWarning, stacklevel=2)


# ------------------------------------------------------------------------------


_CONFIG_MAPPING: Dict[str, Tuple] = {
    "access_token": ("FBUTILS_ACCESS_TOKEN", None),
    "app_domain": ("FBUTILS_APP_DOMAIN", None),
    "app_id": ("FBUTILS_APP_ID", None),
    "app_scope": ("FBUTILS_APP_SCOPE", None),
    "app_secret": ("FBUTILS_APP_SECRET", None),
    "app_secretproof": ("FBUTILS_APP_SECRETPROOF", 0),
    "debug": ("FBUTILS_DEBUG", 0),
    "fb_api_version": ("FBUTILS_FB_API_VERSION", None),
    "oauth_code_redirect_uri": ("FBUTILS_REDIRECT_URI_OAUTH_CODE", None),
    "oauth_token_redirect_uri": ("FBUTILS_REDIRECT_URI_OAUTH_TOKEN", None),
    "secure_only": ("FBUTILS_SECURE_ONLY", True),
    "ssl_verify": ("FBUTILS_SSL_VERIFY", True),
}
_CONFIG_BOOLS: List[str] = [
    "app_secretproof",
    "debug",
    "secure_only",
    "ssl_verify",
]

# use this for checks
_CONFIG_MAPPING_REVERSE = {v[0]: k for k, v in _CONFIG_MAPPING.items()}


def parse_environ(
    requires: Optional[List[str]] = None,
) -> Dict:
    config: Dict[str, Any] = {}
    for _key, _settings in _CONFIG_MAPPING.items():
        (_env_var, _default) = _settings
        config[_key] = os.environ.get(_env_var, _default)

    for _key in _CONFIG_BOOLS:
        if not isinstance(config[_key], bool):
            config[_key] = bool(int(config[_key]))

    if requires:
        if not isinstance(requires, list):
            raise ValueError("`requries` must be a list")
        _requires = set(requires)
        _all_options = set(_CONFIG_MAPPING_REVERSE.keys())
        if not _requires.issubset(_all_options):
            _unknown = _requires - _all_options
            raise ValueError("`requries` contains unknown elements: %s" % str(_unknown))
        _errors = []
        for _key in _requires:
            _setting = _CONFIG_MAPPING_REVERSE[_key]
            if config[_setting] is None:
                _errors.append(_key)
        if _errors:
            errors = ", ".join(["`%s`" % i for i in _errors])
            raise ValueError("Missing required items: %s" % errors)
    return config
