"""Unit tests for the Caldera v5 compatibility fix in SamlLoginHandler.handle_login.

These tests exercise *only* the branching logic in handle_login and stub out the
LoginHandlerInterface base class plus all collaborator services. They are
intended to run without a Caldera checkout, libxmlsec1, or any SAML stack —
they prove the patch in isolation.

For full integration coverage, run tests/test_saml.py inside a populated Caldera
tree (see tox.ini).

Regression: mitre/saml#9 — Caldera v5's login form POSTs empty ``username=&password=``
fields on initial page load. The pre-patch key-presence check
(``'username' not in data``) treated empty values as a credential submission
and fell through to the default handler, which then redirected the user
away from the SAML SSO redirect.
"""
import importlib.util
import os
import sys
import types
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---- Stub the Caldera base class so we can import SamlLoginHandler without a
# Caldera checkout on the path. The real class is a thin marker interface.

class _LoginHandlerInterfaceStub:
    def __init__(self, services, name):
        self.services = services
        self.name = name


def _ensure_pkg(name, path=None):
    pkg = sys.modules.setdefault(name, types.ModuleType(name))
    if path is not None:
        pkg.__path__ = [path]
    elif not hasattr(pkg, '__path__'):
        pkg.__path__ = []
    return pkg


_ensure_pkg('app')
_ensure_pkg('app.service')
_ensure_pkg('app.service.interfaces')
_iface_mod = types.ModuleType('app.service.interfaces.i_login_handler')
_iface_mod.LoginHandlerInterface = _LoginHandlerInterfaceStub
sys.modules['app.service.interfaces.i_login_handler'] = _iface_mod


# ---- Load the patched plugin module by absolute path.

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PLUGIN_FILE = os.path.join(_REPO_ROOT, 'app', 'saml_login_handler.py')

_ensure_pkg('plugins', os.path.dirname(_REPO_ROOT))
_ensure_pkg('plugins.saml', _REPO_ROOT)
_ensure_pkg('plugins.saml.app', os.path.join(_REPO_ROOT, 'app'))

_spec = importlib.util.spec_from_file_location(
    'plugins.saml.app.saml_login_handler', _PLUGIN_FILE
)
_module = importlib.util.module_from_spec(_spec)
sys.modules['plugins.saml.app.saml_login_handler'] = _module
_spec.loader.exec_module(_module)
SamlLoginHandler = _module.SamlLoginHandler


# ---- Fixtures.

def _make_request(post_data):
    """Build a MagicMock request whose ``await request.post()`` yields ``post_data``."""
    request = MagicMock()
    request.post = AsyncMock(return_value=post_data)
    return request


def _make_handler(default_handler=None):
    """Construct a SamlLoginHandler with mocked services and login_redirect.

    If ``default_handler`` is provided, it is wired as
    ``services['auth_svc'].default_login_handler.handle_login`` so the
    fall-through branch can be observed.
    """
    auth_svc = MagicMock()
    if default_handler is not None:
        auth_svc.default_login_handler = MagicMock()
        auth_svc.default_login_handler.handle_login = default_handler
    handler = SamlLoginHandler(services={'auth_svc': auth_svc})
    handler.handle_login_redirect = AsyncMock()
    return handler


# ---- Tests.

@pytest.mark.asyncio
async def test_v5_empty_creds_triggers_saml_redirect():
    """v5 regression: empty username/password fields must redirect to IdP."""
    handler = _make_handler()
    request = _make_request({'username': '', 'password': ''})

    await handler.handle_login(request)

    handler.handle_login_redirect.assert_awaited_once_with(request)


@pytest.mark.asyncio
async def test_v5_empty_username_only_triggers_saml_redirect():
    """Defensive: empty username with stray password value still SSO-redirects."""
    handler = _make_handler()
    request = _make_request({'username': '', 'password': 'whatever'})

    await handler.handle_login(request)

    handler.handle_login_redirect.assert_awaited_once_with(request)


@pytest.mark.asyncio
async def test_v5_empty_password_only_triggers_saml_redirect():
    """Defensive: empty password with stray username value still SSO-redirects."""
    handler = _make_handler()
    request = _make_request({'username': 'red', 'password': ''})

    await handler.handle_login(request)

    handler.handle_login_redirect.assert_awaited_once_with(request)


@pytest.mark.asyncio
async def test_v4_missing_keys_still_triggers_saml_redirect():
    """Backwards compat: pre-v5 behavior (no creds keys at all) unchanged."""
    handler = _make_handler()
    request = _make_request({})

    await handler.handle_login(request)

    handler.handle_login_redirect.assert_awaited_once_with(request)


@pytest.mark.asyncio
async def test_real_creds_falls_through_to_default_handler():
    """Real credentials must still bypass SAML and use default handler."""
    default_handler = AsyncMock()
    handler = _make_handler(default_handler=default_handler)
    request = _make_request({'username': 'red', 'password': 'admin'})

    await handler.handle_login(request)

    handler.handle_login_redirect.assert_not_awaited()
    default_handler.assert_awaited_once()
