from dnif.consumer import AsyncHttpConsumer
from dnif.logger import DnifLogger
from idstools import unified2
from idstools import maps
import sys
import logging
import time
import sys, os
import datetime
import Pyro4
import pygeoip
import re
import logging
import redis
import ast
import json

LOGFILE = "/var/log/snort-agent-idstool.log"
logging.basicConfig(filename=LOGFILE, level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

r = redis.Redis()
sysdata = r.hget('csltuconfig','system')
sysconfig = ast.literal_eval(sysdata)

pyrodata = r.hget('csltuconfig','Pyro')
pyroconfig = ast.literal_eval(pyrodata)
url = 'http://172.16.10.156:9234/json/receive'

DevSrcIP = sysconfig['localip']

#Deff :
now_clock = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

sigIDDict = {}

dt_evt = {}

classmap = maps.ClassificationMap()
#Load Classidication.config from both SNORT and ET-Rules
classmap.load_from_file(open("/etc/snort/classification.config"))
classmap.load_from_file(open("/etc/snort/etrules/classification.config"))
#To check how many classification is loade uncomment below line
logging.warning("[+] No. of classificaton loaded = %s " %(classmap.size()))
# Set to go : Call using --> classmap.get(<ClassID>)
#======== End of Classification init =============

sigmap = maps.SignatureMap()
#Load gid & sid files from both SNORT and ET-Rules
sigmap.load_generator_map(open("/etc/snort/gen-msg.map"))
sigmap.load_generator_map(open("/etc/snort/etrules/gen-msg.map"))
sigmap.load_signature_map(open("/etc/snort/sid-msg.map"))
sigmap.load_signature_map(open("/etc/snort/etrules/sid-msg.map"))
#To check how many Signature-maps is loade uncomment below line
logging.warning("[+] No. of Signature loaded = %s " %(sigmap.size()))
# Set to go : Call using --> classmap.get(<ClassID>)
#======== End of Signature-map init =============

#Init GEOIP data for IP details
geo_lite_city = pygeoip.GeoIP('GeoLiteCity.dat')
geo_ip_asn = pygeoip.GeoIP('GeoIPASNum.dat')
logging.warning('Loaded latest ASN and City info')

nowtimedom = datetime.datetime.now()
updatedurationdom = datetime.timedelta(minutes=5)
updatetimedom = nowtimedom + updatedurationdom
# FOR ASN and City Info
nowtime = datetime.datetime.now()
updateduration = datetime.timedelta(hours=6)
updatetime = nowtime + updateduration
####FOR ASN and City Info######

repdict = {}
try:
    logging.info("Adultlist Start")
    f = open("nsprofile/fddict.json",'r')
    jj = f.readlines()
    f.close()
    repdict = json.loads(jj[0])
    logging.info("Repdict Updated")
except IOError,e:
    logging.info("Repdict not Found")
    repdict = {}
#Start IDSTool to read log :
reader = unified2.SpoolEventReader("/var/log/snort", "snort.u2.*",follow=True,delete=False,bookmark=True)
httplist = []
max_buffer_size=1024
nowtime = datetime.datetime.now()
timeduration = datetime.timedelta(seconds=5)
endtime = nowtime + timeduration
dlog = DnifLogger(AsyncHttpConsumer(url, buffer_size=max_buffer_size))
dlog.start()
try:
    for event in reader:
        if datetime.datetime.now() > updatetime:
            try:
                geo_lite_city = pygeoip.GeoIP('GeoLiteCity.dat')
                geo_ip_asn = pygeoip.GeoIP('GeoIPASNum.dat')
                logging.warning('Loaded latest ASN and City info')
            except Exception,e:
                print e
            nowtime = datetime.datetime.now()
            updateduration = datetime.timedelta(hours=6)
            updatetime = nowtime + updateduration

        if datetime.datetime.now() > updatetimedom:
            nowtimedom = datetime.datetime.now()
            updatedurationdom = datetime.timedelta(minutes=5)
            updatetimedom = nowtimedom + updatedurationdom
            try:
                logging.info("Adultlist Start")
                f = open("dnsprofile/fddict.json",'r')
                jj = f.readlines()
                f.close()
                repdict = json.loads(jj[0])
                logging.info("Repdict Updated")
            except IOError,e:
                logging.info("Repdict not Found")
                repdict = {}

        dt_evt = {}
        if event['generator-id'] != 1 :
            continue
        signaturemap = sigmap.get(event['generator-id'],event['signature-id'])
        classname = classmap.get(event['classification-id'])

        dt_evt['AtkClass'] = str(classname['name'])
        dt_evt['AtkDesc'] = str(classname['description'])
        dt_evt['AtkMsg'] = str(signaturemap['msg'])
        dt_evt['LogEvent'] = str(signaturemap['msg'])
        dt_evt['EventID'] = str(event['signature-id'])
        CVE =""
        URL =""
        BUG =""
        if signaturemap['ref'] :
            for i in signaturemap['ref'] :
                m = i.split(",")
                if m[0] == 'cve':
                    CVE += m[1] + ","
                elif m[0] == 'url':
                    URL += m[1] + ","
                elif m[0] == 'bugtraq':
                    BUG += m[1] + ","
            if CVE != "" :
                dt_evt['CVE'] = str(CVE[:-1])
            if URL != "" :
                dt_evt['URL'] = str(URL[:-1])
            if BUG != "" :
                dt_evt['BugTraq'] = str(BUG[:-1])
        try:
            for KEY, VALUE in event.items():
                if KEY == 'packets' and VALUE != None:
                    dt_evt['PacketData']= str(VALUE[0]['data']).decode('utf-8', 'ignore').encode('utf-8')
                elif KEY == 'extra-data' :
                    if len(VALUE) > 0 :
                       dt_evt['ExtraData']=str(VALUE).decode('utf-8', 'ignore').encode('utf-8')
                elif KEY == 'protocol' and VALUE != None :
                       dt_evt['Proto'] = str(VALUE)
                elif KEY == 'source-ip' and VALUE != None :
                    rec = None
                    try :
                        rec = geo_lite_city.record_by_addr(VALUE)
                    except Exception, e:
                        logging.warning('IN source geo_lite_city %s'%str(e))

                    if rec != None :
                        t_arry = """[%s,%s]""" %(rec['longitude'],rec['latitude'])
                        dt_evt['SrcLOC'] = t_arry
                        dt_evt['SrcCN'] = rec['country_code']
                    else:
                        dt_evt['SrcLOC'] = 'NA'
                        dt_evt['SrcCN'] = 'NA'

                    asn_obj = None
                    try:
                        asn_obj = geo_ip_asn.asn_by_addr(VALUE)
                    except Exception,e:
                        logging.warning('IN source asn_obj %s'%str(e))

                    if asn_obj != None :
                        match = None
                        match = re.findall("^(AS.*?)\s+(.*)", asn_obj)
                        dt_evt['SrcAS'] = match[0][0]
                        dt_evt['SrcISP'] = match[0][1]
                    else:
                        dt_evt['SrcAS'] = 'NA'
                        dt_evt['SrcISP'] = 'NA'

                    dt_evt['SrcIP'] = VALUE

                elif KEY == 'destination-ip' and VALUE != None :
                    rec = None
                    try:
                        rec = geo_lite_city.record_by_addr(VALUE)
                    except Exception,e:
                        logging.warning('IN destination geo_lite_city %s'%str(e))

                    if rec != None :
                        t_arry = """[%s,%s]""" %(rec['longitude'],rec['latitude'])
                        dt_evt['DstLOC'] = t_arry
                        dt_evt['DstCN'] = rec['country_code']
                    else:
                        dt_evt['DstLOC'] = 'NA'
                        dt_evt['DstCN'] = 'NA'

                    asn_obj = None

                    try:
                        asn_obj = geo_ip_asn.asn_by_addr(VALUE)
                    except Exception,e:
                        logging.warning('IN destination asn_obj %s'%str(e))

                    if asn_obj != None :
                        match = None
                        match = re.findall("^(AS.*?)\s+(.*)", asn_obj)
                        dt_evt['DstAS'] = match[0][0]
                        dt_evt['DstISP'] = match[0][1]
                    else:
                        dt_evt['DstAS'] = 'NA'
                        dt_evt['DstISP'] = 'NA'

                    dt_evt['DstIP'] = VALUE

                elif KEY == 'sport-itype' and VALUE != None :
                    dt_evt['SrcPort'] = str(VALUE)
                elif KEY == 'dport-icode' and VALUE != None :
                    dt_evt['DstPort'] = str(VALUE)
                elif KEY == 'priority' and VALUE != None :
                    dt_evt['Severity'] = str(VALUE)
                elif KEY == 'vlan-id' and VALUE != None :
                    dt_evt['VlanID'] = str(VALUE)
                dt_evt['LogType'] = 'DPI'
                dt_evt['LogID'] = 45
                dt_evt['PStatus'] = 'PAD'
                dt_evt['LogName'] = 'NMSNORT'
                dt_evt['ProductType'] = 'TM'
                dt_evt['ScopeID'] = sysconfig['scopeid']
                dt_evt['EvtLen'] = len(str(event))
                dt_evt['CNAMTime'] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
                dt_evt['DevSrcIP'] = DevSrcIP
            srcip = '.'.join(dt_evt['SrcIP'].split('.')[:3])
            dstip = '.'.join(dt_evt['DstIP'].split('.')[:3])
            if (srcip in repdict.keys()) and (dstip in repdict.keys()):
                dt_evt['Flow'] = 'Internal'
            elif srcip in repdict.keys():
                dt_evt['Flow'] = 'Egress'
            elif dstip in repdict.keys():
                dt_evt['Flow'] = 'Ingress'
            else:
                if len(repdict.keys()) > 0:
                    dt_evt['Flow'] = 'Unknown'

            httplist.append(dt_evt)
            if 'PacketData' in dt_evt:
                dt_evt.pop('PacketData', None)
            logging.warning('%s' %dt_evt)
            rpr = dlog.log(dt_evt)
            print rpr
            if (datetime.datetime.now() > endtime) or (len(httplist) > 15000):
                nowtime = datetime.datetime.now()
                timeduration = datetime.timedelta(seconds=5)
                endtime = nowtime + timeduration
                logging.warning('%s list' %httplist)
                dlog.log(httplist)
                httplist = []

        except Exception,e:
            logging.warning('Error %s'%str(e))
            time.sleep(2)
except Exception,e:
    logging.warning('Error %s'%str(e))
    time.sleep(2)
