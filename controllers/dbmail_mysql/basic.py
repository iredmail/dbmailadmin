# Author: Zhang Huangbin <zhb@iredmail.org>

import os
import time
from socket import getfqdn
from urllib import urlencode
import web
from libs import __url_latest_dbmail_mysql__, __version_dbmail_mysql__, __no__, __id__
from libs import iredutils, settings, languages
from libs.dbmail_mysql import core, decorators, admin as adminlib, connUtils


cfg = web.iredconfig
session = web.config.get('_session')


if session.get('enableAmavisdQuarantine') or session.get('enableAmavisdLoggingIntoSQL'):
    from libs.amavisd import quarantine, log as amavisdlog


class Login:
    def GET(self):
        if session.get('logged') is False:
            i = web.input(_unicode=False)

            # Show login page.
            return web.render(
                'login.html',
                languagemaps=languages.getLanguageMaps(),
                msg=i.get('msg'),
            )
        else:
            raise web.seeother('/dashboard')

    def POST(self):
        # Get username, password.
        i = web.input(_unicode=False)

        username = web.safestr(i.get('username').strip())
        password = str(i.get('password').strip())
        save_pass = web.safestr(i.get('save_pass', 'no').strip())

        auth = core.Auth()
        auth_result = auth.auth(username=username, password=password)

        if auth_result[0] is True:
            # Config session data.
            web.config.session_parameters['cookie_name'] = 'iRedAdmin-Pro'
            # Session expire when client ip was changed.
            web.config.session_parameters['ignore_change_ip'] = False
            # Don't ignore session expiration.
            web.config.session_parameters['ignore_expiry'] = False

            if save_pass == 'yes':
                # Session timeout (in seconds).
                web.config.session_parameters['timeout'] = 86400    # 24 hours
            else:
                # Expire session when browser closed.
                web.config.session_parameters['timeout'] = 600      # 10 minutes

            web.logger(msg="Login success", event='login',)
            raise web.seeother('/dashboard/checknew')
        else:
            session['failedTimes'] += 1
            web.logger(msg="Login failed.", admin=username, event='login', loglevel='error',)
            raise web.seeother('/login?msg=%s' % web.urlquote(auth_result[1]))


class Logout:
    def GET(self):
        session.kill()
        raise web.seeother('/login')


class Dashboard:
    @decorators.require_login
    def GET(self, checknew=None):
        i = web.input(_unicode=False,)

        if checknew is not None:
            self.checknew = True
        else:
            self.checknew = False

        # Get network interface related infomation.
        netif_data = {}
        try:
            import netifaces
            ifaces = netifaces.interfaces()
            for iface in ifaces:
                addr = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addr.keys():
                    data = addr[netifaces.AF_INET][0]
                    try:
                        netif_data[iface] = {'addr': data['addr'], 'netmask': data['netmask'], }
                    except:
                        pass
        except:
            pass

        # Check new version.
        newVersionInfo = (None, )
        if session.get('domainGlobalAdmin') is True and self.checknew is True:
            try:
                curdate = time.strftime('%Y-%m-%d')
                vars = dict(date=curdate)

                r = web.admindb.select('updatelog', vars=vars, where='date >= $date',)
                if len(r) == 0:
                    urlInfo = {
                        'a': cfg.general.get('webmaster', session.get('username', '')),
                        'v': __version_dbmail_mysql__,
                        'o': __no__,
                        'f': __id__,
                        'host': getfqdn(),
                    }

                    url = __url_latest_dbmail_mysql__ + '?' + urlencode(urlInfo)
                    newVersionInfo = iredutils.getNewVersion(url)

                    # Always remove all old records, just keep the last one.
                    web.admindb.delete('updatelog', vars=vars, where='date < $date',)

                    # Insert updating date.
                    web.admindb.insert('updatelog', date=curdate,)
            except Exception, e:
                newVersionInfo = (False, str(e))

        # Get numbers of domains, users, aliases.
        numberOfDomains = 0
        numberOfUsers = 0
        numberOfAliases = 0

        try:
            adminLib = adminlib.Admin()

            numberOfDomains = adminLib.getNumberOfManagedAccounts(accountType='domain')
            numberOfUsers = adminLib.getNumberOfManagedAccounts(accountType='user')
            numberOfAliases = adminLib.getNumberOfManagedAccounts(accountType='alias')
        except:
            pass

        # Get numbers of existing messages and quota bytes.
        # Set None as default, so that it's easy to detect them in Jinja2 template.
        totalMessages = None
        totalBytes = None
        try:
            tmpConn = core.MySQLWrap()
            totalBytes = tmpConn.getUsedBytesMessages()
        except Exception:
            pass

        # Get records of quarantined mails.
        amavisdQuarantineCount = 0
        amavisdQuarantineRecords = []
        if session.get('enableAmavisdQuarantine') is True:
            quarantineLib = quarantine.Quarantine()

            # Show only 10 records in Dashboard.
            qr = quarantineLib.getRecordsOfQuarantinedMails(sizelimit=10, countOnly=True,)
            if qr[0] is True:
                (amavisdQuarantineCount, amavisdQuarantineRecords) = qr[1]

        # Get number of incoming/outgoing emails in latest 24 hours.
        numberOfIncomingMails = 0
        numberOfOutgoingMails = 0
        numberOfVirusMails = 0
        topSenders = []
        topRecipients = []

        if session.get('enableAmavisdLoggingIntoSQL') is True:
            allReversedDomainNames = []

            amavisdLogLib = amavisdlog.Log()

            # Get all managed domain names and reversed names.
            allDomains = []
            connutils = connUtils.Utils()
            result_all_domains = connutils.getManagedDomains(session.get('username'), domainNameOnly=True)
            if result_all_domains[0] is True:
                allDomains += result_all_domains[1]

            allReversedDomainNames = amavisdLogLib.reverseDomainNames(allDomains)
            numberOfIncomingMails = amavisdLogLib.getNumberOfIncomingMails(allReversedDomainNames, 86400)
            numberOfOutgoingMails = amavisdLogLib.getNumberOfOutgoingMails(allReversedDomainNames, 86400)
            numberOfVirusMails = amavisdLogLib.getNumberOfVirusMails(allReversedDomainNames, 86400)
            topSenders = amavisdLogLib.getTopUser(
                reversedDomainNames=allReversedDomainNames,
                logType='sent',
                timeLength=86400,
                number=10,
            )
            topRecipients = amavisdLogLib.getTopUser(
                reversedDomainNames=allReversedDomainNames,
                logType='received',
                timeLength=86400,
                number=10,
            )

        return web.render(
            'dashboard.html',
            version=__version_dbmail_mysql__,
            hostname=getfqdn(),
            uptime=iredutils.getServerUptime(),
            loadavg=os.getloadavg(),
            netif_data=netif_data,
            newVersionInfo=newVersionInfo,
            amavisdQuarantineCount=amavisdQuarantineCount,
            #amavisdQuarantineRecords=amavisdQuarantineRecords,
            numberOfDomains=numberOfDomains,
            numberOfUsers=numberOfUsers,
            numberOfAliases=numberOfAliases,
            totalMessages=totalMessages,
            totalBytes=totalBytes,
            numberOfIncomingMails=numberOfIncomingMails,
            numberOfOutgoingMails=numberOfOutgoingMails,
            numberOfVirusMails=numberOfVirusMails,
            topSenders=topSenders,
            topRecipients=topRecipients,
            removeQuarantinedInDays=settings.AMAVISD_REMOVE_QUARANTINED_IN_DAYS,
        )


class Search:
    @decorators.require_login
    def GET(self):
        i = web.input()
        return web.render('dbmail_mysql/search.html', msg=i.get('msg'), )

    @decorators.csrf_protected
    @decorators.require_login
    def POST(self):
        i = web.input(accountType=[], accountStatus=[],)
        searchString = i.get('searchString', '')
        if len(searchString) == 0:
            raise web.seeother('/search?msg=EMPTY_STRING')

        accountType = i.get('accountType', [])
        accountStatus = i.get('accountStatus', [])

        try:
            connutils = connUtils.Utils()
            qr = connutils.search(searchString,
                                  accountType=accountType,
                                  accountStatus=accountStatus,
                                  )
            if qr[0] is False:
                return web.render(
                    'mysql/search.html',
                    msg=qr[1],
                    searchString=searchString,
                )
        except Exception, e:
            return web.render(
                'mysql/search.html',
                msg=str(e),
                searchString=searchString,
            )

        # Group account types.
        admins = qr[1].get('admin', [])
        users = qr[1].get('user', [])
        aliases = qr[1].get('alias', [])
        allGlobalAdmins = qr[1].get('allGlobalAdmins', [])
        totalResults = len(admins) + len(users) + len(aliases)

        return web.render(
            'dbmail_mysql/search.html',
            searchString=searchString,
            totalResults=totalResults,
            admins=admins,
            users=users,
            aliases=aliases,
            allGlobalAdmins=allGlobalAdmins,
            msg=i.get('msg'),
        )


class OperationsFromSearchPage:
    @decorators.require_login
    def GET(self, *args, **kw):
        raise web.seeother('/search')

    @decorators.csrf_protected
    @decorators.require_login
    def POST(self, accountType):
        accountType = web.safestr(accountType)  # user, alias
        i = web.input(_unicode=False, mail=[])

        # Get action.
        action = i.get('action', None)
        if action not in ['enable', 'disable', 'delete', ]:
            raise web.seeother('/search?msg=INVALID_ACTION')

        # Get list of accounts which has valid format.
        accounts = [web.safestr(v).lower() for v in i.get('mail', []) if iredutils.isEmail(web.safestr(v))]

        # Raise earlier to avoid SQL query.
        if not accounts:
            raise web.seeother('/search?msg=INVALID_MAIL')

        domains = set([v.split('@', 1)[-1] for v in accounts])

        # Get managed accounts.
        if not session.get('domainGlobalAdmin'):
            # Get list of managed domains.
            connutils = connUtils.Utils()
            qr = connutils.getManagedDomains(
                admin=session.get('username'),
                domainNameOnly=True,
                listedOnly=True,
            )
            if qr[0] is True:
                domains = [d for d in domains if d in qr[1]]
                accounts = [v for v in accounts if v.split('@', 1)[-1] in domains]
            else:
                raise web.seeother('/search?msg=%s' % str(qr[1]))

        if not accounts:
            raise web.seeother('/search?msg=INVALID_MAIL')

        conn = core.MySQLWrap()
        if action in ['enable', ]:
            qr = conn.setAccountStatus(accounts=accounts, accountType=accountType, active=True)
        elif action in ['disable', ]:
            qr = conn.setAccountStatus(accounts=accounts, accountType=accountType, active=False)
        elif action in ['delete', ]:
            qr = conn.deleteAccounts(accounts=accounts, accountType=accountType)

        if qr[0] is True:
            raise web.seeother('/search?msg=SUCCESS')
        else:
            raise web.seeother('/search?msg=%s' % str(qr[1]))
