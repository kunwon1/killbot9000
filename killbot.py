from gevent import monkey
monkey.patch_all()

import sys
import sopel.module
from sopel.tools import stderr

import socket
import gevent
import dns.resolver
sys.path.append('/usr/local/lib/python2.7/site-packages')
from dnsbl import Base

#TODO gateway cloak support

blacklists = [
        "dnsbl.dronebl.org",
        "cbl.abuseat.org",
        "http.dnsbl.sorbs.net",
        "misc.dnsbl.sorbs.net",
        "socks.dnsbl.sorbs.net",
        "proxies.dnsbl.sorbs.net",
        "tor.efnet.org",
        "rbl.efnet.org",
        "rbl.efnetrbl.org",
        "torexit.dan.me.uk",
        "tor.dnsbl.sectoor.de",
        "xbl.spamhaus.org",
        ]

dnsResolver = None

def setup(bot):
    global dnsResolver
    dnsResolver = dns.resolver.Resolver()

@sopel.module.commands('helloworld')
def helloworld(bot, trigger):
    bot.say('Hello, world!')

@sopel.module.commands('host')
@sopel.module.priority('low')
@sopel.module.require_admin
@sopel.module.example('.host google.com')
def doManualLookup(bot, trigger):
    if not trigger.sender == bot.config.killbot.control_channel:
        return
    else:
        list = getIPList(trigger.group(2))
        rep = " ".join(list)            
        bot.reply(rep)

@sopel.module.commands('rbl')
@sopel.module.priority('low')
@sopel.module.require_admin
@sopel.module.example('.rbl 8.8.8.8 or .rbl google.com')
def doRBLLookup(bot, trigger):
    stderr('foo')
    if not trigger.sender == bot.config.killbot.control_channel:
        return
    else:
        stderr('doing lookup, got %s' % trigger.group(2))
        checkResults = baseRBLLookup(trigger.group(2))
        rep = ""
        for r in checkResults:
            if r[1] != False:
                if r[1] != None:
                    rep += "HIT: %s %s " % (r[0], r[1])
        if rep == "":
            rep = "No hits"
        bot.reply(rep)

@sopel.module.event('JOIN')
@sopel.module.rule('.*')
@sopel.module.priority('high')
def processJoin(bot, trigger):
    ips = getIPList(trigger.host)

    for ip in ips:
        bot.msg(bot.config.killbot.control_channel, 'doing lookup on %s' % ip)
        blResult = baseRBLLookup(ip)
        ban = False
        why = ''
        for r in blResult:
            stderr(r)
            if r[1] != False:
                if r[1] != None:
                    ban = True
                    why += "HIT: %s %s " % (r[0], r[1])
        if ban == True:
            bot.msg(bot.config.killbot.control_channel, 'I would have banned %s on %s because of a blacklist hit.' % (trigger.nick, trigger.sender))
            bot.msg(bot.config.killbot.control_channel, why)
        else:
            bot.msg(bot.config.killbot.control_channel, '%s is clean.' % trigger.host)


def baseRBLLookup(ip):
    backend = Base(ip=ip, providers=blacklists)
    return backend.check()

def getIPList(hostname):

    #takes a hostname or ip address, returns list containing
    #ip addresses that hostname resolves to, or original ip address
    #always returns a list

    ipList = []

    if hostname.find('/') != -1:
        #this is a cloak, dns lookups don't matter
        return ipList

    if validateIP(hostname) == True:
        ipList.append('%s' % hostname)
        return ipList

    else:
        stderr('resolving %s' % hostname)
        try:
            ipv4 = dnsResolver.query(hostname,'A')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            ipv4 = []
        try:
            ipv6 = dnsResolver.query(hostname,'AAAA')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            ipv6 = []
        for a in ipv4:
            stderr('    resolved A record to %s' % a)
            ipList.append('%s' % a)
        for aaaa in ipv6:
            stderr('    resolved AAAA record to %s' % aaaa)
            ipList.append('%s' % aaaa)
        return ipList

    #for some reason we couldn't find anything
    stderr('getIPList fell through for %s' % hostname)
    return ipList

def validateIP(address):
    return validateIPV4(address) or validateIPV6(address)

def validateIPV4(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False

    return True

def validateIPV6(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:
        return False
    return True

