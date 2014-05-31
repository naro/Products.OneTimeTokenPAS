import sys

from Acquisition import aq_base
from AccessControl.SecurityInfo import ClassSecurityInfo
from Globals import InitializeClass, DTMLFile
from base64 import urlsafe_b64decode as decodestring

from Products.CMFCore.utils import getToolByName
from Products.PluggableAuthService.plugins.CookieAuthHelper \
    import CookieAuthHelper as BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.interfaces.plugins import \
    IExtractionPlugin, IAuthenticationPlugin

from Products.CMFPlone.utils import log
from Products.OneTimeTokenPAS.config import *

# This hacked PlonePAS collection of plugins was mostly ripped
# from other plugins, especially from CookieAuthHelper


def try_decode(token):
    """ Try to decode token, but add one or two = until not successfull
        Returns decoded string and new (correct) token
    """
    new_token = token
    decoded = ''
    try:
        decoded = decodestring(new_token)
    except:
        new_token = new_token + '='
        try:
            decoded = decodestring(new_token)
        except:
            new_token = new_token + '='
            try:
                decoded = decodestring(new_token)
            except:
                pass
    if not decoded:
        # no change
        new_token = token

    return decoded, new_token


def manage_addOneTimeTokenPlugin(self, id, title='',
                                 RESPONSE=None, **kw):
    """Create an instance of a one time token cookie helper.
    """

    self = self.this()

    o = OneTimeTokenPlugin(id, title, **kw)
    self._setObject(o.getId(), o)
    o = getattr(aq_base(self), id)

    if RESPONSE is not None:
        RESPONSE.redirect('manage_workspace')

manage_addOneTimeTokenForm = DTMLFile("www/OneTimeTokenForm", globals())


class UsernameStorage:
    """Store the username in this object, so it can be stored in the session"""

    def _setUsername(self, username):
        self.__username = username

    def _getUsername(self):
        return self.__username


class OneTimeTokenPlugin(BasePlugin):
    """Multi-plugin which adds ability to override the updating of cookie via
    a setAuthCookie method/script.
    """

    _properties = ({'id': 'title',
                    'label': 'Title',
                    'type': 'string',
                    'mode': 'w',
                    },
                   )

    meta_type = 'One Time Token Plugin'
    security = ClassSecurityInfo()

    session_var = '__ac'

    def __init__(self, id, title=None):
        self._setId(id)
        self.title = title

    security.declarePrivate('extractCredentials')
    def extractCredentials(self, request):

        """ Extract credentials from cookie or 'request'. """
        #log( 'extractCredentials')

        creds = {}
        username = None

        tokenTool = getToolByName(self, 'onetimetoken_storage')
        sdm = getToolByName(self, 'session_data_manager', None)
        if sdm is None:
            session = request.SESSION
        else:
            session = sdm.getSessionData(create=False)

        ob = None

        if sdm.hasSessionData():
            ob = session.get(self.session_var)

        if ob is not None and isinstance(ob, UsernameStorage):
            username = ob._getUsername()
            #log( "session username: %s" % username )

        # do not log ++theme and ++resource stuff
        do_log = '++' not in request.URL0

        if username is None:
            loginCode = request.get('logincode')

            if not loginCode:
                return None  # not authenticated

            decoded, new_loginCode = try_decode(loginCode)

            if do_log:
                url = request.URL0
                if loginCode != new_loginCode:
                    log("Token: url: %s loginCode old: %s new: %s decoded to: %s" % (url, loginCode, new_loginCode, decoded))
                else:
                    log("Token: url: %s loginCode: %s decoded to: %s" % (url, loginCode, decoded))

            try:
                username = tokenTool.verifyToken(new_loginCode)
            except Exception, e:
                if do_log:
                    log("Error, token tool refused token: %s" % str(e))

            if not username:
                return None  # not authenticated

            #log( "token username: %s" % username )

            userstorage = UsernameStorage()
            userstorage._setUsername(username)
            session = sdm.getSessionData(create=True)
            session[self.session_var] = userstorage

        creds['remote_host'] = request.get('REMOTE_HOST', '')
        try:
            creds['remote_address'] = request.getClientAddr()
        except AttributeError:
            creds['remote_address'] = request.get('REMOTE_ADDR', '')

        creds['login'] = username

        # log( "returning username: %s" % username )

        return creds

    def authenticateCredentials(self, credentials):

        if 'extractor' in credentials and \
           credentials['extractor'] != self.getId():
            return (None, None)

        login = credentials.get('login')

        #log( "returning credentials: (%s, %s)" % (login, login) )

        return (login, login)

    security.declarePrivate('resetCredentials')
    def resetCredentials(self, request, response):
        """ Clears credentials"""
        sdm = getToolByName(self, 'session_data_manager', None)
        if sdm is None:
            session = request.SESSION
        else:
            session = sdm.getSessionData(create=False)

        if session and (self.session_var in session):
            del session[self.session_var]


classImplements(OneTimeTokenPlugin,
                IExtractionPlugin,
                IAuthenticationPlugin,
                )

InitializeClass(OneTimeTokenPlugin)
