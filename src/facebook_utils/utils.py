import os
import re
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union
import warnings


# ==============================================================================


RE_api_version_fixable = re.compile(r"\d+\.\d+")
RE_api_version_valid = re.compile(r"v\d+\.\d+")


def warn_future(message: str) -> None:
    warnings.warn(message, FutureWarning, stacklevel=2)


# ------------------------------------------------------------------------------
TYPE_MAPPING_ENTRY = Tuple[str, Union[int, bool, None]]
TYPE_CONFIG_PARSED = Dict[str, Union[str, bool, None]]

_CONFIG_MAPPING: Dict[str, TYPE_MAPPING_ENTRY] = {
    "access_token": ("FBUTILS_ACCESS_TOKEN", None),
    "app_domain": ("FBUTILS_APP_DOMAIN", None),
    "app_id": ("FBUTILS_APP_ID", None),
    "app_scope": ("FBUTILS_APP_SCOPE", None),
    "app_secret": ("FBUTILS_APP_SECRET", None),
    "debug": ("FBUTILS_DEBUG", 0),
    "enable_secretproof": ("FBUTILS_ENABLE_SECRETPROOF", 1),
    "fb_api_version": ("FBUTILS_FB_API_VERSION", None),
    "oauth_code_redirect_uri": ("FBUTILS_REDIRECT_URI_OAUTH_CODE", None),
    "oauth_token_redirect_uri": ("FBUTILS_REDIRECT_URI_OAUTH_TOKEN", None),
    "secure_only": ("FBUTILS_SECURE_ONLY", True),
    "ssl_verify": ("FBUTILS_SSL_VERIFY", True),
}
_CONFIG_BOOLS = (
    "debug",
    "enable_secretproof",
    "secure_only",
    "ssl_verify",
)

# use this for checks
_CONFIG_MAPPING_REVERSE: Dict[str, str] = {v[0]: k for k, v in _CONFIG_MAPPING.items()}


def parse_environ(requires: Optional[List[str]] = None) -> TYPE_CONFIG_PARSED:
    config: TYPE_CONFIG_PARSED = {}
    for _key, _settings in _CONFIG_MAPPING.items():
        (_env_var, _default) = _settings
        config[_key] = os.environ.get(_env_var, str(_default))

    for _key in _CONFIG_BOOLS:
        _v = config[_key]
        if not isinstance(_v, bool):
            if _v is None:
                config[_key] = False
            elif isinstance(_v, str):
                config[_key] = bool(int(_v))
            elif isinstance(_v, int):
                config[_key] = bool(_v)

    if requires:
        if not isinstance(requires, list):
            raise ValueError("`requires` must be a list")
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
