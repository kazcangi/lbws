"""Package lbws to interact with livebox."""

import sys
import functools
import json
import datetime
from collections import namedtuple
from importlib import reload

from lbws.exceptions import LbwsException, LbwsNotConnectedError

##
# @brief python 3 est requis
if sys.version_info.major < 3:
    raise "Must be using Python 3"

##
# @brief règle un problème de sortie vers un fichier
if sys.stdout.encoding is None:
    reload(sys)
    sys.setdefaultencoding('utf-8') # pylint: disable=E1101

##
# @brief fonction lambda pour afficher sur stderr
error = functools.partial(print, file=sys.stderr) # pylint: disable=C0103

##
# @brief requests n'est pas dans la distrib standard de Python3, d'où le traitement spécifique
#        pour l'import de cette librairie
try:
    import requests
    import requests.utils
except ImportError as exc:
    error("erreur:", exc)
    error("Installez http://www.python-requests.org/ :")
    print("   pip install requests")
    sys.exit(2)

##
# @brief niveau de détail, -v pour l'augmenter
VERBOSITY = 0

def debug(level, *args):
    """Affiche un message de debug
        @param level niveau de détail
        @param args
    """
    if VERBOSITY >= level:

        red = '\033[91m'
        #green = '\033[92m'
        yellow = '\033[93m'
        #light_purple = '\033[94m'
        purple = '\033[95m'
        end = '\033[0m'

        #print(*args, file=sys.stderr)

        if level <= 1:
            sys.stderr.write(yellow)
        elif level == 2:
            sys.stderr.write(purple)
        else:
            sys.stderr.write(red)

        sys.stderr.write(' '.join(args))
        sys.stderr.write(end)
        sys.stderr.write('\n')

#####################


def auth_required(func):
    """Decorator to check if instance is authenticated."""
    @functools.wraps(func)
    def inner(self, *args, **kwargs):
        """Authenticate if not authenticated."""
        if self.token is None and self.session is None:
            self.auth()

        return func(self, *args, **kwargs)
    return inner

def _json_object_hook(dct):
    return namedtuple('X', dct.keys())(*dct.values())

def json2obj(data):
    """Create object from json"""
    return json.loads(data, object_hook=_json_object_hook)


class Lbws:
    """Class to deal with Livebox."""
    # pylint: disable=R0902

    def __init__(self, host=None, user=None, password=None, livebox_version='lb4'):
        """Init Livebox with host, user and password if defined."""
        self.host = host
        self.user = user
        self.password = password
        self.livebox_version = livebox_version

        self.headers = {'Content-Type': 'application/json'}
        self.sah_headers = {
            'X-Prototype-Version':'1.7',
            'Content-Type':'application/x-sah-ws-1-call+json; charset=UTF-8',
            'Accept':'text/javascript'
            }
        self.session = None
        self.token = None
        self.cookies = None
        self._dsl_mib = None
        self._wan_status = None
        self._ppp_mib = None
        self._dsl_stats = None
        self._voip_sip = None
        self._wifi_status = None
        self._tv_status = None
        self._users = None

    @staticmethod
    def _check_req(req):
        if req['status'] is None:
            raise LbwsException('Error when retrieving informations.')

    def _post(self, path, args=None, raw=False, silent=False, **kwargs):
        # nettoie le chemin de la requête
        lpath = str.replace(path or "sysbus", ".", "/")
        if lpath[0] == "/":
            lpath = lpath[1:]

        if lpath[0:7] != "sysbus/":
            lpath = "sysbus/" + lpath

        parameters = {}
        if not args is None:
            for i in args:
                parameters[i] = args[i]

        data = {}
        data['parameters'] = parameters

        # l'ihm des livebox 4 utilise une autre API, qui fonctionne aussi sur les lb2 et lb3
        sep = lpath.rfind(':')
        data['service'] = lpath[0:sep].replace('/', '.')
        if data['service'][0:7] == "sysbus.":
            data['service'] = data['service'][7:]
        data['method'] = lpath[sep+1:]
        lpath = 'ws'

        # envoie la requête avec les entêtes qui vont bien
        debug(1, "requête: %s with %s" % (lpath, str(data)))
        tstamp = datetime.datetime.now()

        tmp = self.session.post(
            'http://{0}/ws'.format(self.host),
            headers=self.sah_headers,
            data=json.dumps(data),
            **kwargs
            )
        debug(2, "durée requête: %s" % (datetime.datetime.now() - tstamp))
        tmp = tmp.content

        # il y a un truc bien moisi dans le nom netbios de la Time Capsule
        # probable reliquat d'un bug dans le firmware de la TC ou de la Livebox
        tmp = tmp.replace(b'\xf0\x44\x6e\x22', b'aaaa')

        if raw is True:
            return tmp

        tmp = tmp.decode('utf-8', errors='replace')

        try:
            req = json.loads(tmp)
        except json.JSONDecodeError:
            if not silent:
                error("erreur:", sys.exc_info()[0])
                error("mauvais json:", tmp)
            return

        apercu = str(req)
        if len(apercu) > 50:
            apercu = apercu[:50] + "..."
        debug(1, "réponse:", apercu)

        if not 'errors' in req['result']:
            debug(1, "-------------------------")
            return req['result']
        else:
            if not silent:
                error("erreur:", req)
            return None



    def _get(self, path, args=None, raw=False, silent=False, **kwargs):
        data = '{"parameters":{}}'
        # nettoie le chemin de la requête
        lpath = str.replace(path or "sysbus", ".", "/")
        if lpath[0] == "/":
            lpath = lpath[1:]

        if lpath[0:7] != "sysbus/":
            lpath = "sysbus/" + lpath

        if args is None:
            params = {'_restDepth': '-1'}

        debug(1, "requête: %s" % (lpath))
        tstamp = datetime.datetime.now()
        tmp = self.session.get(
            'http://{0}/{1}'.format(self.host, lpath),
            headers=self.headers,
            data=data,
            params=params,
            **kwargs
            )
        debug(2, "durée requête: %s" % (datetime.datetime.now() - tstamp))
        tmp = tmp.content

        # il y a un truc bien moisi dans le nom netbios de la Time Capsule
        # probable reliquat d'un bug dans le firmware de la TC ou de la Livebox
        tmp = tmp.replace(b'\xf0\x44\x6e\x22', b'aaaa')

        if raw is True:
            return tmp

        tmp = tmp.decode('utf-8', errors='replace')
        if tmp.find("}{"):
            debug(2, "listes json multiples")
            tmp = "[" + tmp.replace("}{", "},{") + "]"

        try:
            req = json.loads(tmp)
        except json.JSONDecodeError:
            if not silent:
                error("erreur:", sys.exc_info()[0])
                error("mauvais json:", tmp)
            return

        apercu = str(req)
        if len(apercu) > 50:
            apercu = apercu[:50] + "..."
        debug(1, "réponse:", apercu)
        debug(1, "-------------------------")

        return req

    def auth(self):
        """Call authenticate on Livebox.

        user, host and password must be set.
        """
        if not self.user or not self.password or not self.host:
            raise LbwsException('User and/or password not set')

        self.session = requests.Session()

        if self.livebox_version != 'lb4':
            auth = {'username':self.user, 'password':self.password}
            debug(2, "auth with", str(auth))
            req = self.session.post(
                'http://{0}/authenticate'.format(self.host),
                params=auth,
                headers=self.headers,
                )
            debug(2, "auth return", req.text)
        else:
            sah_headers = {
                'Content-Type':'application/x-sah-ws-1-call+json',
                'Authorization':'X-Sah-Login'
                }
            auth = ('{"service":"sah.Device.Information",'
                    '"method":"createContext","parameters":'
                    '{"applicationName":"so_sdkut","username":"%s",'
                    '"password":"%s"}}') % (self.user, self.password)
            req = self.session.post(
                'http://{0}/ws'.format(self.host),
                data=auth,
                headers=sah_headers,
                )

        if req.status_code != requests.codes.ok and not 'contextID' in req.json()['data']: # pylint: disable=E1101
            raise LbwsException('Authentication error : %s' % req.text)

        self.token = req.json()['data']['contextID']
        self.headers['X-Context'] = self.token
        self.sah_headers = {
            'X-Context':self.token,
            'Authorization':'X-Sah %s' % (self.token),
            'X-Prototype-Version':'1.7',
            'Content-Type':'application/x-sah-ws-1-call+json; charset=UTF-8',
            'Accept':'text/javascript'
            }
        self.cookies = req.cookies

        # vérification de l'authentification
        req = self.session.post(
            'http://{0}/'.format(self.host) + 'sysbus/Time:getTime',
            headers=self.sah_headers,
            data='{"parameters":{}}'
            )
        if req.json()['result']['status'] is True:
            return True
        else:
            raise LbwsException('Authentication error : %s' % req.text)

    @auth_required
    def logout(self):
        """Logout from livebox.

        POST on http://{0}/logout
        """
        sah_headers = {
            'Content-Type':'application/x-sah-ws-1-call+json',
            'Authorization':'X-Sah-Logout %s' % (self.token)
            }
        auth = ('{"service":"sah.Device.Information","method":"releaseContext",'
                '"parameters":{"applicationName":"so_sdkut"}}')
        req = self.session.post(
            'http://{0}/ws'.format(self.host),
            data=auth,
            headers=sah_headers,
            )
        if req.status_code == requests.codes.ok and req.json()['status'] == 0:  # pylint: disable=E1101
            self.token = None
            return True

        return False

    @property
    @auth_required
    def dsl_mib(self):
        """Get DSL Infos from Livebox.

        POST parameters on http://{0}/sysbus/NeMo/Intf/data:getMIBsCall
        :return: an object with attributes :
            CurrentProfile
            DataPath
            DownstreamAttenuation
            DownstreamCurrRate
            DownstreamMaxRate
            DownstreamNoiseMargin
            DownstreamPower
            FirmwareVersion
            InterleaveDepth
            LastChange
            LastChangeTime
            LinkStatus
            ModulationHint
            ModulationType
            StandardUsed
            StandardsSupported
            UPBOKLE
            UpstreamAttenuation
            UpstreamCurrRate
            UpstreamMaxRate
            UpstreamNoiseMargin
            UpstreamPower
        :rtype: object

        """
        if self._dsl_mib is None:
            args = {"mibs":"dsl", "flag":"", "traverse":"down"}

            req = self._post(
                'NeMo.Intf.data:getMIBs',
                args=args,
                )

            self._check_req(req)

            if 'dsl0' in req['status']['dsl']:
                self._dsl_mib = json2obj(json.dumps(req['status']['dsl']['dsl0']))
            else:
                self._dsl_mib = None

        return self._dsl_mib

    @property
    @auth_required
    def wan_status(self):
        """Get WAN status

        POST parameters on http://{0}/sysbus/NMC:getWANStatus

        :result: a JSON structure with keys :
            ConnectionState
            RemoteGateway
            LinkState
            DNSServers
            Protocol
            LastConnectionError
            IPAddress
            LinkType
            MACAddress
            IPv6Address
        :rtype: json
        """

        if self._wan_status is None:
            req = self._post(
                'NMC:getWANStatus',
                )

            self._check_req(req)
            self._wan_status = json2obj(json.dumps(req['data']))

        return self._wan_status

    @property
    @auth_required
    def ppp_mib(self):
        """Get ppp Infos from Livebox.

        POST parameters on http://{0}/sysbus/NeMo/Intf/data:getMIBsCall
        :return: a JSON structure with keys :
            PPPoESessionID
            TransportType
            RemoteIPAddress
            IPv6CPEnable
            ConnectionTrigger
            IPCPEnable
            LastConnectionError
            PPPoEACName
            DNSServers
            IdleDisconnectTime
            LCPEchoRetry
            LCPEcho
            MaxMRUSize
            ConnectionStatus
            LastChangeTime
            IPv6CPLocalInterfaceIdentifier
            IPv6CPRemoteInterfaceIdentifier
            PPPoEServiceName
            LastChange
            LocalIPAddress
            Username
        :rtype: json
        """

        if self._ppp_mib is None:
            args = {"mibs":"ppp"}

            req = self._post(
                'NeMo.Intf.data:getMIBs',
                args=args,
                )

            self._check_req(req)

            if 'ppp' in req['status']:
                self._ppp_mib = json2obj(json.dumps(req['status']['ppp']['ppp_data']))
            else:
                self._ppp_mib = None

        return self._ppp_mib

    @property
    @auth_required
    def dsl_stats(self):
        """Get DSL stats from Livebox.

        POST on http://{0}/sysbus/NeMo/Intf/dsl0:getDSLStats

        :result: a JSON structure with keys :
            LossOfFraming
            TransmitBlocks
            HECErrors
            ATUCCRCErrors
            CellDelin
            ErroredSecs
            ReceiveBlocks
            CRCErrors
            InitErrors
            LinkRetrain
            ATUCFECErrors
            SeverelyErroredSecs
            FECErrors
            InitTimeouts
            ATUCHECErrors
        :rtype: json
        """

        if self._dsl_stats is None:
            req = self._post(
                'NeMo.Intf.dsl0:getDSLStats',
                )
            self._check_req(req)
            self._dsl_stats = json2obj(json.dumps(req['status']))

        return self._dsl_stats

    @property
    @auth_required
    def voip_sip(self):
        """Get VoIP informations fron livebox."""
        if self._voip_sip is None:
            req = self._post(
                'VoiceService.VoiceApplication:listTrunks',
                )

            self._check_req(req)

            item = next((item for item in req['status'] if item['name'] == 'SIP-Trunk'), None)
            #if not item:
                #raise LbwsException('Error when retrieving SIP-Trunk informations.')
            if item:
                self._voip_sip = json2obj(json.dumps(req['status'][0]['trunk_lines']))
            else:
                self._voip_sip = None

        return self._voip_sip

    @property
    @auth_required
    def wifi_status(self):
        """Get WiFi status from livebox."""
        if self._wifi_status is None:
            req = self._post(
                'NMC.Wifi:get',
                )

            self._check_req(req)

            self._wifi_status = json2obj(json.dumps(req['status']))

        return self._wifi_status

    @property
    @auth_required
    def tv_status(self):
        """Get TV status

        """

        if self._tv_status is None:
            req = self._post(
                'NMC.OrangeTV:getIPTVStatus',
                )

            self._tv_status = json2obj(json.dumps(req['data']))

        return self._tv_status


    @auth_required
    def mibs(self):
        """Get all MIBS from Livebox.

        POST parameters on http://{0}/sysbus/NeMo/Intf/data:getMIBs
        """

        req = self._post(
            'NeMo.Intf.data:getMIBs',
            )

        self._check_req(req)

        return req['status']

    @property
    @auth_required
    def users(self):
        """Get users defined on Livebox."""

        if self._users is None:
            req = self._post(
                'UserManagement:getUsers'
                )

            self._check_req(req)

            self._users = json2obj(json.dumps(req['status']))

        return self._users

    def reboot(self):
        """Reboot the livebox."""

        req = self._post(
            'NMC:reboot',
            )

        if req.status_code == requests.codes.ok:  # pylint: disable=E1101
            self.token = None
            return True

        return False
