import os
import sys
import logging
import urllib2
import base64
import ConfigParser
from lxml import etree
from time import gmtime, strftime
from datetime import date, timedelta

REPORT_LIST_URL = "https://qualysapi.qualys.com/msp/scan_report_list.php"
REPORT_FETCH_URL = "https://qualysapi.qualys.com/msp/scan_report.php"
LOG_LEVEL = logging.DEBUG
LOG_FILENAME =  os.path.join(os.environ['SPLUNK_HOME'], 'var', 'log', 'splunk', 'qualysscan.log')
LOG_FORMAT = "[%(asctime)s] %(name)s %(levelname)s: %(message)s"
logging.basicConfig(filename=LOG_FILENAME,level=LOG_LEVEL,format=LOG_FORMAT)
logger = logging.getLogger('qualysscan')


def getSeenFilePath():
    '''
    Returns the path to the seen_reports.log file that contains the list of reports that have been seen.
    '''
    return os.path.join(os.environ['SPLUNK_HOME'], 'var', 'lib', 'splunk', 'persistentstorage', 'qualys', 'seen_report.log')

def getLocalConfPath():
    '''
    Returns the path to the local config directory.
    '''
    pathname = os.path.dirname(sys.argv[0])
    pathname = os.path.abspath(pathname)
    pathname = os.path.join(pathname, '..', 'local', 'qualys.conf')
    return os.path.normpath(pathname)

def haveSeenReport(ref):
    '''
    Tests if we have seen this report yet.
    '''
    fullSeenPath = getSeenFilePath()
    if not os.path.isfile(fullSeenPath):
        return False

    with open(fullSeenPath) as f:
        seenReports = f.read().splitlines()
        for report in seenReports:
            if report == ref:
                return True
    return False

def addSeenReport(ref):
    '''
    Adds a report to the list of seen reports.
    '''
    fullSeenPath = getSeenFilePath()
    if not os.path.isdir(os.path.dirname(fullSeenPath)):
        os.makedirs(os.path.dirname(fullSeenPath))
    with open(fullSeenPath, 'a') as f:
        f.write(ref + '\n')

def getreport(user, password, reference):
    '''
    Retrieves a scan report.
    '''
    scan_req = urllib2.Request(REPORT_FETCH_URL + '?ref=%s' % reference)
    authString = base64.encodestring('%s:%s' % (user, password))
    authheader = 'Basic %s' % authString
    scan_req.add_header('Authorization', authheader)
    scan_req.add_header('X-Requested-With', 'Splunk')

    # auth is set up, let's grab a list
    report_xml = urllib2.urlopen(scan_req)
    report = etree.parse(report_xml)

    return report

def getreportlist(user, password, daysOld):
    '''
    Retrieves a list of the scans for the given user. Will only get scans newer than the daysOld parameter.
    '''
    # build the URL
    logger.debug('Starting report list. Getting scans older than %s days' % daysOld)
    since = date.today() - timedelta(days=daysOld)
    qUrl = '%s?since_datetime=%s' % (REPORT_LIST_URL,since)
    logger.debug('This makes our report since = %s' % since)

    # build the auth handler
    passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
    passman.add_password(None, qUrl, user, password)
    auth_handler = urllib2.HTTPBasicAuthHandler(passman)

    opener = urllib2.build_opener(auth_handler)
    urllib2.install_opener(opener)

    list_req = urllib2.Request(qUrl)
    logger.debug('URL for report list request is %s' % list_req.get_full_url())
    authString = base64.encodestring('%s:%s' % (user, password))[:-1]
    authheader = 'Basic %s' % authString
    list_req.add_header('Authorization', authheader)
    list_req.add_header('X-Requested-With', 'Splunk')

    # auth is set up, let's grab a list
    logger.debug('Opening list')
    report_list = urllib2.urlopen(list_req)
    logger.debug('Got list')
    reports = etree.parse(report_list)

    return reports

def listreportinfo(report, ref):
    '''
    List the info about the passed report from the XML Header info
    '''
    timestamp = getscantime(report)
    reportString = "timestamp=%s scan_id=%s report_type=SCAN" % (timestamp, ref)
    scan_header = report.find('HEADER')

    for option in scan_header.getiterator('OPTION_PROFILE'):
        for option_profile_title in option.getiterator('OPTION_PROFILE_TITLE'):
            reportString = '%s profile_title="%s"' % (reportString, option_profile_title.text)
    for header in scan_header.getiterator('KEY'):
        if 'value' in header.attrib:
            key = header.attrib['value'].lower()
            value = header.text
            if header.attrib['value'] != 'date':
                reportString = '%s %s="%s"' % (reportString, key, value)
    print reportString

def getscantime(report):
    '''
    Returns the time the scan was started.
    '''
    # just in case
    retval = strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())

    scan_header = report.find('HEADER')
    for header in scan_header.getiterator('KEY'):
        if 'value' in header.attrib:
            if header.attrib['value'] == 'DATE':
                return header.text
    return retval

def listreports(reports):
    '''
    Returns a list of the finished reports.
    '''
    retval = []
    for scan in reports.getiterator('SCAN_REPORT'):
        if scan.attrib['status'] == 'FINISHED':
            retval.append(scan.attrib['ref'])

    return retval

def listvulns(report, ref):
    '''
    Lists the vulns found in a report.
    '''
    # first we need to get the timestamp to be used for the events. Note that
    # qualys doesn't provide the time on a per vuln basis,
    timestamp = getscantime(report)
    for dest in report.getiterator('IP'):
        current_dest = dest.attrib['value']
        current_dest_dns = 'unknown'
        if 'name' in dest.attrib:
            if dest.attrib['name'] != 'No registered hostname':
                current_dest_dns = dest.attrib['name']

        # Grab the OS data
        current_dest_os = 'unknown'
        if dest.find("OS") != None:
            current_dest_os = dest.find("OS").text

        # let's get a look at services
        if dest.find('SERVICES') != None:
            for infolist in dest.getiterator('SERVICES'):
                for cur_group in infolist.getiterator('CAT'):
                    current_category = cur_group.attrib['value']
                    for service in cur_group.getiterator('SERVICE'):
                        qid = 'unknown'
                        if 'number' in service.attrib:
                            qid = service.attrib['number']
                        signature = service.find("TITLE").text
                        result = service.find("RESULT").text

                        print 'timestamp=%s scan_id=%s report_type=SERVICE dest=%s dest_dns=%s dest_os="%s" category="%s" qid=%s signature="%s" result="%s"' % (timestamp, ref, current_dest, current_dest_dns, current_dest_os, current_category, qid, signature, result)

        # now to them vulns, getting them by category
        # Validate that the vulns exist
        if dest.find('VULNS') != None:
            for vulnlist in dest.getiterator('VULNS'):
                for category in vulnlist.getiterator('CAT'):
                    current_category = category.attrib['value']
                    current_proto = 'unknown'
                    current_port = 'unknown'
                    if 'protocol' in category.attrib:
                        current_proto = category.attrib['protocol']
                    if 'port' in category.attrib:
                        current_port = category.attrib['port']
                    # finally, some vulns
                    for vuln in category.getiterator('VULN'):
                        severity = 'unknown'
                        signature = 'unknown'
                        qid = 'unknown'
                        cve = 'unknown'
                        if 'number' in vuln.attrib:
                            qid = vuln.attrib['number']
                        if 'severity' in vuln.attrib:
                            severity = vuln.attrib['severity']
                        if 'cveid' in vuln.attrib:
                            cve = vuln.attrib['cveid']
                        # now all we need is the signature
                        signature = vuln.find("TITLE").text
                        if vuln.find("RESULT") is not None:
                            vuln_result = vuln.find("RESULT").text
                        else:
                            vuln_result = 'unknown'
                        print 'timestamp=%s scan_id=%s report_type=VULN dest=%s dest_dns=%s dest_port=%s dest_proto=%s dest_os="%s" category="%s" qid=%s signature="%s" severity_id=%s cve=%s result="%s"' % (timestamp, ref, current_dest, current_dest_dns, current_port, current_proto, current_dest_os, current_category, qid, signature, severity, cve, vuln_result)

if __name__ == '__main__':

    logger.info("Starting input run")
    configFile = getLocalConfPath()
    if not os.path.isfile(configFile):
        raise IOError('config file not found in local dir')
        logger.error('No config file found')
        sys.exit(1)
    logger.debug('Using config file %s' % configFile)

    config = ConfigParser.SafeConfigParser()
    config.read(configFile)
    username = config.get('qualys', 'username')
    password = config.get('qualys', 'password')
    daysOld = int(config.get('qualys', 'days'))
    logger.debug('Read in config info')

    logger.info('Getting report list')
    try:
        reportList = getreportlist(username, password, daysOld)
        logger.debug('Got reports')
        reports = listreports(reportList)
        logger.debug('Found %s finished scan reports' % len(reports))
        for ref in reports:
            # This is where the logic goes to only get the ones we haven't seen before
            if not haveSeenReport(ref):
                logger.info('Getting report %s' % ref)
                report = getreport(username, password, ref)
                logger.debug('Getting vulns for scan %s' % ref)
                listreportinfo(report, ref)
                listvulns(report, ref)
                logger.debug('Adding %s to the list of seen reports' % ref)
                addSeenReport(ref)
    except Exception, err:
        logger.error(err)
    logger.info('Finished input run')

