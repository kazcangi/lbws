# lbws
Quick and dirty python library to interact with Orange Livebox

Example :

```


from lbws import Lbws
from datetime import date, timedelta, datetime

if __name__ == '__main__':
    version = "1.0.0"

    lb = Lbws("192.168.1.1", "admin", "your password")

    print("Date et heure locale  : {0}".format(datetime.now()))
#    print("Statut connexion ppp  : {0} ({1})".format(lb.ppp_mib.ConnectionStatus, lb.ppp_mib.TransportType))
    print("Statut du lien DSL    : {0}".format(lb.wan_status.LinkState))
    print("Type de protocol      : {0}".format(lb.wan_status.Protocol))
    print("Etat synchronisation  : {0}".format(lb.dsl_mib.LinkStatus))
    print("Type de connexion     : {0} ({1})".format(lb.dsl_mib.ModulationHint, lb.dsl_mib.ModulationType))
#    print("User ppp              : {0}".format(lb.ppp_mib.Username))

    print("Débit descendant      : {0} Kb/s (marge de bruit : {1} dB)".format(
        lb.dsl_mib.DownstreamCurrRate,
        lb.dsl_mib.DownstreamNoiseMargin / 10
        ))
    print("Débit montant         : {0} Kb/s (marge de bruit : {1} dB)".format(
        lb.dsl_mib.UpstreamCurrRate,
        lb.dsl_mib.UpstreamNoiseMargin / 10
        ))
    print("Synchronisé depuis    : {0} ({1})".format(
        str(timedelta(seconds=lb.dsl_mib.LastChange)),
        (datetime.now() - timedelta(seconds=lb.dsl_mib.LastChange)).strftime('%d/%m/%Y %H:%M:%S')
        ))

    print("Etat WiFi             : {0}".format(lb.wifi_status.Status))
    print("Etat TV               : {0}".format(lb.tv_status.IPTVStatus))
    for i in lb.voip_sip:
        print("Etat TOIP             : {0} {1} ({2})".format(i.name, i.status, i.directoryNumber))
    print("IPV4 Publique         : {0}".format(lb.wan_status.IPAddress))
    print("IPV6 Publique         : {0}".format(lb.wan_status.IPv6Address))
    print("CRC Errors            : {0} - ATUC CRC Errors : {1}".format(lb.dsl_stats.CRCErrors, lb.dsl_stats.ATUCCRCErrors,))
    for i in lb.users:
        print("User                  : {0} (type {1}) - Groupes : {2}".format(i.name, i.type, i.groups))
    print()

    lb.logout()
