'''
Python implementation of Riffle client side libraries.

Fork of wamp. Used for convenience, high level operations, and more.
'''

'''
Wamp utility methods.
'''


import base64
import json
import os
import urlparse

from OpenSSL import crypto
from autobahn.twisted.wamp import ApplicationSession, ApplicationRunner
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred
from autobahn.wamp.types import RegisterOptions, SubscribeOptions, CallOptions, PublishOptions, ComponentConfig

from autobahn.twisted import wamp, websocket
from twisted.internet import reactor
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.internet.ssl import ClientContextFactory

from riffle import crypto as rcrypto
from riffle.address import Action, Endpoint
from riffle.address import Domain

# Try pulling in credentials from environment variables.
# TOKEN is a random string received from the auth appliance.
# KEY is the path to an RSA private key.
EXIS_TOKEN = os.environ.get("EXIS_TOKEN", None)
EXIS_KEY   = os.environ.get("EXIS_KEY", None)

## New additions
FABRIC_URL = "wss://node.exis.io:8000/wss"
SOFTPERM = False

def setDevFabric(url="ws://ubuntu@ec2-52-26-83-61.us-west-2.compute.amazonaws.com:8000/ws"):
    global FABRIC_URL, SOFTPERM

    FABRIC_URL = url
    SOFTPERM = True


class FabricClientFactory(websocket.WampWebSocketClientFactory, ReconnectingClientFactory):
    # factor and jitter are two variables that control the exponential backoff.
    # The default values in ReconnectingClientFactory seem reasonable.
    initialDelay = 1
    maxDelay = 600

    def clientConnectionFailed(self, connector, reason):
        ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)

    def clientConnectionLost(self, connector, reason):
        ReconnectingClientFactory.clientConnectionLost(self, connector, reason)


class FabricSessionFactory(wamp.ApplicationSessionFactory):
    def __init__(self, config, deferred=None):
        super(FabricSessionFactory, self).__init__(config)
        self.dee = deferred

    def __call__(self, *args, **kwargs):
        sess = super(FabricSessionFactory, self).__call__(*args, **kwargs)
        sess.dee = self.dee
        return sess


class FabricSession(ApplicationSession):

    """ Temporary base class for crossbar implementation """

    def __init__(self, config=None):
        ApplicationSession.__init__(self, config=config)

        self.pdid = config.extra['pdid']
        self.authid = config.extra.get('authid', self.pdid)

        # Need some idea of top level domain so we know which bouncer to call
        self.topLevelDomain = Domain(config.extra.get('topLevelDomain', 'xs.demo'))

        # extra overrides the environment variable
        self.token = config.extra.get('token', None)
        if self.token is None:
            self.token = EXIS_TOKEN

        keySource = config.extra.get('key', None)
        if keySource is None:
            keySource = EXIS_KEY

        if keySource is None:
            self.key = None
        else:
            self.key = getPrivateKey(keySource)


    @classmethod
    def start(klass, pdid, address=None, realm='crossbardemo', extra=None,
            start_reactor=False, debug=False, retry=True):
        '''
        Creates a new instance of this session and attaches it to the router
        at the given address and realm. The pdid is set manually now since we trust
        clients. Excessively.

        For now the realm is automatically set as a demo realm since we are not
        using multiple realms.

        Optional values that can be passed through extra:
        authid: ID to use for authentication (login or key checking).  This can
            be used when setting pdid to be a subdomain of one's domain.  For
            example, the user "pd.damouse" can connect to the fabric as
            pdid="pd.damouse.aardvark" by supplying his credentials for
            authid="pd.damouse".
        '''
        if not address: 
            address = FABRIC_URL

        # Configuration
        if extra is None:
            extra = {}
        else:
            extra = dict.copy(extra)

        extra['pdid'] = u'' + pdid

        dee = Deferred()

        component_config = ComponentConfig(realm=pdid, extra=extra)
        session_factory = FabricSessionFactory(config=component_config, deferred=dee)
        session_factory.session = klass

        transport_factory = FabricClientFactory(session_factory, debug=debug, debug_wamp=debug)
        
        if not retry:
            transport_factory.maxRetries = 0

        uri = urlparse.urlparse(address)
        transport_factory.host = uri.hostname
        transport_factory.port = uri.port
        transport_factory.isSecure = (uri.scheme == 'wss')

        context_factory = ClientContextFactory()

        websocket.connectWS(transport_factory, context_factory)

        if start_reactor:
            reactor.run()

        return dee

    def join(self, realm):
        authmethods = []

        if self.key is not None:
            authmethods.append(u'signature')

        if self.token is not None:
            authmethods.append(u'token')

        if SOFTPERM: 
            authmethods = []

        super(FabricSession, self).join(realm, authmethods=[], authid=self.authid)

    def leave(self):
        # Do not retry if explicitly asked to leave.
        self._transport.factory.maxRetries = 0
        super(FabricSession, self).leave()

    @inlineCallbacks
    def onJoin(self, details):
        yield

        # Reset exponential backoff timer after a successful connection.
        self._transport.factory.resetDelay()

        # Inform whoever created us that the session has finished connecting.
        # Useful in situations where you need to fire off a single call and not a
        # full wamplet
        try:
            if self.dee is not None:
                yield self.dee.callback(self)
        except:
            # print 'No onJoin deferred callback set.'
            pass

    def onChallenge(self, details):
        print 'Challenging'

        if details.method == "signature":
            if self.key is None:
                return u''
            nonce = details.extra['challenge']
            hmethod = str(details.extra['hash'])
            sig = rcrypto.sign_message(self.key, nonce, hmethod)
            sig = base64.b64encode(sig)
            return unicode(sig)

        elif details.method == "token":
            if self.token is None:
                return u''
            else:
                return unicode(self.token)

        else:
            return u''

    @inlineCallbacks
    def addBouncerPermissions(self, agent, actions):
        """
            Adds permissions into bouncer so other domains can contact endpoints of this appliance
                agent: the agent who can call this appliance,
                actions: a list of actions that can be called (need to be converted to full endpoints)
        """

        # Convert actions to full endpoints
        #print "self.pdid: %s actions: %s" % (self.pdid, actions)
        perms = [str(Endpoint(domain=self.pdid, action=action))  for action in actions]
        #print "perms: %s" % perms
        bouncerEndpoint = str(self.topLevelDomain + 'Bouncer' + Action('setPerm'))
        #print "bouncerEndpoint, agent, perms= %s %s %s" % (bouncerEndpoint, agent, perms)
        if agent is not None:
            agent = str(agent)
        ret = yield self.absCall(bouncerEndpoint, agent, perms)

        returnValue(ret)

    ###################################################
    # Overridden CX interaction methods
    ###################################################

    def publish(self, pdid, topic, *args, **kwargs):
        # kwargs['options'] = PublishOptions(disclose_me=True)
        args = (self.pdid,) + args
        topic = _prepend(pdid, topic)
        #out.info('riff: (%s) publish (%s)' % (self.pdid, topic,))
        return ApplicationSession.publish(self, topic, *args, **kwargs)

    def subscribe(self, handler, pdid, topic=None, options=None):
        topic = _prepend(self.pdid, topic)
        #out.info('riff: (%s) subscribe (%s)' % (self.pdid, topic,))
        return ApplicationSession.subscribe(self, handler, topic=topic, options=options)

    def call(self, pdid, procedure, *args, **kwargs):
        # kwargs['options'] = CallOptions(disclose_me=True)
        args = (self.pdid,) + args
        procedure = _prepend(pdid, procedure)
        #out.info('riff: (%s) calling (%s)' % (self.pdid, procedure,))
        return ApplicationSession.call(self, procedure, *args, **kwargs)

    def register(self, endpoint, procedure=None, options=None):
        # options = RegisterOptions(details_arg='session')
        procedure = _prepend(self.pdid, procedure)
        #out.info('riff: (%s) register (%s)' % (self.pdid, procedure,))
        return ApplicationSession.register(self, endpoint, procedure=procedure, options=options)

    ###################################################
    # Absolute (not relative to your PDID)
    # In other words, all these methods require a permission check
    ###################################################
    def absPublish(self, topic, *args, **kwargs):
        #out.info('riff: (%s) publish (%s)' % (self.pdid, topic,))
        return ApplicationSession.publish(self, u'' + topic, *args, **kwargs)

    def absSubscribe(self, handler, topic=None, options=None):
        #out.info('riff: (%s) subscribe (%s)' % (self.pdid, topic,))
        return ApplicationSession.subscribe(self, handler, topic=u'' + topic, options=options)

    def absCall(self, procedure, *args, **kwargs):
        #out.info('riff: (%s) calling (%s)' % (self.pdid, procedure,))
        return ApplicationSession.call(self, u'' + procedure, *args, **kwargs)

    def absRegister(self, endpoint, procedure=None, options=None):
        #out.info('riff: (%s) registering (%s)' % (self.pdid, procedure,))
        return ApplicationSession.register(self, endpoint, procedure=u'' + procedure, options=options)


class ApplianceSession(FabricSession):
    def __init__(self, config):
        super(ApplianceSession, self).__init__(config)
        self.__config = config.extra

    def __del__(self):
        print("Appliance session {} deleted.".format(self.pdid))

    def getOption(self, name):
        if name in self.__config:
            return self.__config[name]
        else:
            return os.environ.get(name, None)

    @inlineCallbacks
    def onJoin(self, details):
        yield self.register(self.cleanup, "cleanup")
        yield self.register(self.getUsage, "getUsage")
        yield self.grantPermissionCleanup()
        yield self.notifyLauncher("joined")
        yield super(ApplianceSession, self).onJoin(details)

    @inlineCallbacks
    def onLeave(self, details):
        yield self.notifyLauncher("left")
        yield super(ApplianceSession, self).onLeave(details)

    @inlineCallbacks
    def grantPermissionCleanup(self):
        """
        Grant permission for this appliance's launcher to call cleanup.
        """
        launcher = self.getOption('LAUNCHER')
        bouncer = self.getOption('BOUNCER')
        
        if launcher is not None and bouncer is not None:
            cleanup = self.pdid + "/cleanup"
            setPerm = bouncer + "/setPerm"
            yield self.absCall(setPerm, launcher, cleanup, verb="c")

    @inlineCallbacks
    def notifyLauncher(self, state):
        """
        Notify launcher of a state change.
        """
        launcher = self.getOption('LAUNCHER')
        if launcher is not None:
            applianceStateChanged = launcher + "/applianceStateChanged"
            yield self.absCall(applianceStateChanged, state)

    #
    # Appliances should override the following methods.
    #
    # cleanup: delete all appliance state in preparation for removal.
    # getUsage: return a dictionary of usage information.
    #

    def cleanup(self):
        pass

    def getUsage(self):
        return dict()

def getPrivateKey(source):
    """
    Try loading private key from file or PEM-encoded string.
    """

    # Source is already a key?
    if isinstance(source, crypto.PKey):
        return source

    if os.path.exists(source):
        try:
            key = rcrypto.load_key_from_file(source)
            return key
        except OSError as error:
            # Probably means the key does not exist.
            pass

    else:
        try:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, source)
            return key
        except Exception as error:
            pass

    return None


def _prepend(pdid, topic):
    return u'' + pdid + '/' + topic


def main():
    print "Things are stable"

if __name__ == '__main__':
    main()
