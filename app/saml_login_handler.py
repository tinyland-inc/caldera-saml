import logging
from aiohttp import web

from app.service.interfaces.i_login_handler import LoginHandlerInterface

HANDLER_NAME = 'SAML Login Handler'


def load_login_handler(services):
    return SamlLoginHandler(services)


class SamlLoginHandler(LoginHandlerInterface):
    def __init__(self, services):
        super().__init__(services, HANDLER_NAME)
        self.services = services
        self.log = logging.getLogger('saml_login_handler')

    async def handle_login(self, request, **kwargs):
        """Redirects login request to the SAML IdP unless the requester supplied non-empty
        username AND password fields, in which case the default login handler is used.

        Caldera v5's login form POSTs empty ``username=&password=`` fields on initial page
        load, so we must check truthiness rather than key presence (mitre/saml#9). This
        mirrors the semantic Caldera's DefaultLoginHandler already uses
        (app/service/login_handlers/default.py).
        """
        data = await request.post()
        if not data.get('username') or not data.get('password'):
            self.log.debug('Handling SAML login')
            await self.handle_login_redirect(request)
        else:
            auth_svc = self.services.get('auth_svc', None)
            if not auth_svc:
                raise Exception('Auth service not found.')
            self.log.debug('Requester provided login credentials. Using default login handler instead.')
            return await auth_svc.default_login_handler.handle_login(request, kwargs=kwargs)

    async def handle_login_redirect(self, request, **kwargs):
        """Will raise web.HTTPFound for identity provider redirect on success."""
        saml_svc = self.services.get('saml_svc', None)
        if not saml_svc:
            raise Exception('SAML service not found.')
        auth = await saml_svc.get_saml_auth(request)
        redirect = auth.login()
        raise web.HTTPFound(redirect)
