from pymisp import PyMISP, MISPEvent, MISPObject  
from datetime import datetime, timedelta,timezone
from elasticsearch import Elasticsearch
import json, logging, urllib3, os, argparse, sys
from dotenv import load_dotenv

parser = argparse.ArgumentParser(description="Optional parameter --minutes")
parser.add_argument('--minutes', type=int, default=60, help='Minutes (60 default)')

args = parser.parse_args()

print(f"Minutes: {args.minutes}")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def read_last_timestamp(filepath):
    try:
        with open(filepath, 'r') as file:
            timestamp_str = file.read().strip()
            return timestamp_str
    except FileNotFoundError:
        return None


def save_last_timestamp(filepath, timestamp):
    with open(filepath, "w") as f:
        f.write(timestamp + "\n")

def search_logs(es, index, query):
    try:
        response = es.search(index=index, body=query)
        return response
    except Exception as e:
        print(f"Error at index {index}: {e}")
        return None

now_utc = datetime.now(timezone.utc)

now_local = now_utc.astimezone()  

log_today = now_local.strftime("logstash-%Y.%m.%d")
log_yesterday = (now_local  - timedelta(days=1)).strftime("logstash-%Y.%m.%d")
day_today = now_local.day

minutes_ago = now_local - timedelta(minutes=args.minutes)
day_yesterday = minutes_ago.day


filepath = '/tmp/gossip_hive_date_time_limit_range.txt'
datetime_limit_range_str = read_last_timestamp(filepath)

with open('./mitre-enterprise-attack-attack-pattern.json', 'r', encoding='utf-8') as f:
    mitre_enterprise_attack_attack_pattern = json.load(f)

low_limit_range = datetime_limit_range_str if datetime_limit_range_str else f"now-{args.minutes}m"
if not datetime_limit_range_str:
    print(f"No previous timestamp found; will be used 'now-{args.minutes}m'")

high_limit_range = now_utc.strftime('%Y-%m-%dT%H:%M:%S.000Z') 

save_last_timestamp(filepath, high_limit_range)

load_dotenv()
dest_ports_str = os.getenv('DEST_PORT', '21,22,23,25,53,69,80,102,110,123,135,143,161,389,443,445,502,623,631,993,995,1025,1080,1433,1521,1723,1883,1900,2404,2575,3000,3306,3389,4818,5000,5060,5432,5555,5900,6379,6667,8080,8081,8090,8443,9100,9200,10001,11112,11211,25565,44818,47808,50100')
dest_ports = [int(port.strip()) for port in dest_ports_str.split(',')]

excluded_ips_str = os.getenv('EXCLUDED_SRC_IPS', '127.0.0.1')
excluded_ips = [ip.strip() for ip in excluded_ips_str.split(',')]

query = {
  "size": 0,
  "query": {
    "bool": {
      "filter": [

        {
          "range": {
            "@timestamp": {
              "gt": low_limit_range,
              "lte": high_limit_range
            }
          }
        },

        {
          "terms": {
            "type.keyword": ["Suricata","Heralding","Adbhoney","Ciscoasa","CitrixHoneypot","ConPot","Cowrie","Ddospot","Dicompot","Dionaea","ElasticPot","Endlessh","Go-pot","Honeypots","Honeyaml","Ipphoney","Log4pot","Mailoney","Medpot","Miniprint","Redishoneypot","Sentrypeer","Tanner","Wordpot"]
          }
        },
        {
          "bool": {
            "should": [
              { "terms": { "dest_port": dest_ports } },
              { "bool": { "must_not": { "exists": { "field": "dest_port" } } } }
            ],
            "minimum_should_match": 1
          }
        },

        {
          "bool": {
            "must_not": [
              {"terms": {"src_ip": excluded_ips}}
            ]
          }
        }
      ]
    }
  },
  "aggs": {

    "unique_combinations": {
      "composite": {
        "size": 10000,
        "sources": [
          { "src_ip":    { "terms": { "field": "src_ip.keyword"   } } },
          { "type":      { "terms": { "field": "type.keyword"     } } },
          { "dest_port": { "terms": { "field": "dest_port", "missing_bucket": True } } }
        ]
      },
      "aggs": {

        "min_timestamp": {
          "min": { "field": "@timestamp" }
        },

        "first_hit": {
          "top_hits": {
            "size": 1,
            "sort": [
              { "@timestamp": { "order": "asc" } }
            ],
            "_source": ["@timestamp","src_ip","dest_port","type","event_type","data_type","alert.signature","alert.metadata.mitre_technique_id","geoip.country_name","geoip.as_org","geoip.asn","ip_rep","proto","protocol","connection.protocol","action","info","username","password"]
          }
        },

        "sorted_buckets": {
          "bucket_sort": {
            "sort": [
              { "min_timestamp": { "order": "asc" } }
            ],
            "size": 10000
          }
        }
      }
    }
  }
}






es = Elasticsearch(
    os.getenv('ELASTICSEARCH_URL'),
    request_timeout=int(os.getenv('ELASTICSEARCH_TIMEOUT', 30)),
    max_retries=int(os.getenv('ELASTICSEARCH_MAX_RETRIES', 10)),
    retry_on_timeout=os.getenv('ELASTICSEARCH_RETRY_ON_TIMEOUT', 'True').lower() == 'true'

)
MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")
MISP_VERIFY_CERT = os.getenv("MISP_VERIFY_CERT", "False").lower() == "true"
MISP_DISABLE_CORRELATION_SRC_IP = os.getenv('MISP_DISABLE_CORRELATION_SRC_IP', 'False').lower() == 'true'
MISP_DISABLE_CORRELATION_DST_PORT = os.getenv('MISP_DISABLE_CORRELATION_DST_PORT', 'False').lower() == 'true'
MISP_DISABLE_CORRELATION_START_TIME = os.getenv('MISP_DISABLE_CORRELATION_START_TIME', 'False').lower() == 'true'
MISP_DISABLE_CORRELATION_PROTOCOL = os.getenv('MISP_DISABLE_CORRELATION_PROTOCOL', 'False').lower() == 'true'
MISP_ENABLE_COMMENTS_IP = os.getenv('MISP_ENABLE_COMMENTS_IP', 'True').lower() == 'true'
MISP_ENABLE_COMMENTS_SURICATA = os.getenv('MISP_ENABLE_COMMENTS_SURICATA', 'True').lower() == 'true'
MISP_ENABLE_COMMENTS_HONEYPOTS = os.getenv('MISP_ENABLE_COMMENTS_HONEYPOTS', 'True').lower() == 'true'

MISP_EVENT_PAP = os.getenv('MISP_EVENT_PAP', 'GREEN')
MISP_EVENT_TLP = os.getenv('MISP_EVENT_TLP', 'green')

evt_time_str = now_local.strftime('%Y-%m-%d %H:%M')

all_buckets = []

resp = search_logs(es,log_today,query)

if resp is None:
    print(f"ERROR: Could not retrieve data from {log_today}. Exiting.")
    sys.exit(1)

if day_today != day_yesterday:
    resp_yesterday = search_logs(es, log_yesterday, query)
    all_buckets.extend(
          resp_yesterday['aggregations']['unique_combinations']['buckets']
      )

all_buckets.extend(
    resp['aggregations']['unique_combinations']['buckets']
)

if all_buckets:
    misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFY_CERT)
    evt = MISPEvent()
    evt.info    = f"Gossip Hive - {evt_time_str}"
    evt.distribution = int(os.getenv('MISP_DISTRIBUTION', '2'))
    evt.threat_level_id = int(os.getenv('MISP_THREAT_LEVEL_ID', '4'))
    evt.analysis = int(os.getenv('MISP_ANALYSIS', '0'))
    evt = misp.add_event(evt)
    eid = evt['Event']['id']

    for tag in [
        'admiralty-scale:source-reliability="b"',
        'cssa:origin=honeypot',
        'cssa:sharing-class=unvetted',
        f'PAP:{MISP_EVENT_PAP}',
        f'tlp:{MISP_EVENT_TLP}',
        'honeypot-basic:communication-interface=network-interface',
        'honeypot-basic:data-capture=attacks',
        'misp-galaxy:mitre-d3fend="Decoy Network Resource"',
        'misp-galaxy:mitre-d3fend="Standalone Honeynet"'
    ]:
        misp.tag(evt, tag)

    def handle_suricata(hit, src_attr, obj):
        obj.add_attribute('protocol', value=hit['proto'], disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)
        if MISP_ENABLE_COMMENTS_SURICATA:
          obj.comment = f"First attack of {bucket['doc_count']} against {hit['type']}"
        if hit.get('event_type') == 'alert' and 'alert' in hit:
            if MISP_ENABLE_COMMENTS_SURICATA:
                sig = hit['alert'].get('signature')
                if sig:
                    obj.comment += f" (Alert): {sig}"
            mitre_technique_id = hit.get('alert', {}).get('metadata', {}).get('mitre_technique_id')
            if mitre_technique_id and mitre_technique_id in mitre_enterprise_attack_attack_pattern:
                src_attr.add_tag(f'misp-galaxy:mitre-attack-pattern={mitre_enterprise_attack_attack_pattern[mitre_technique_id]}')
        else:
            src_attr.add_tag('misp-galaxy:mitre-attack-pattern="Active Scanning - T1595"')
            src_attr.add_tag('kill-chain:Reconnaissance')


    def handle_adbhoney(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='ADB', disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)
    
    def handle_ciscoasa(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='HTTPS',disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_citrixhoneypot(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='HTTP', disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_conpot(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value=hit['data_type'].upper().replace('_', ' '), disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_cowrie(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=medium')
        port_protocols_cowrie = {
            22: 'SSH',
            23: 'TELNET'              
        }
        if hit['dest_port'] in port_protocols_cowrie:
            obj.add_attribute('protocol', value=port_protocols_cowrie[hit['dest_port']], disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_ddospot(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        port_protocols_ddospot = {
            19: 'CHARGEN',
            53: 'DNS',
            123: 'NTP',
            1900: 'SSDP'
        }
        if hit['dest_port'] in port_protocols_ddospot:
            obj.add_attribute('protocol', value=port_protocols_ddospot[hit['dest_port']], disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_dicompot(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='DICOM',disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_dionaea(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        protocold = hit['connection']['protocol'].upper()
        if protocold.endswith('D'):
            protocold = protocold[:-1]
        obj.add_attribute('protocol', value=protocold, disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_elasticpot(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='ELASTICSEARCH', disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)
        if hit['event_type'] == 'Scan' or hit['event_type'] == 'Head scan':
            src_attr.add_tag('kill-chain:Reconnaissance')
        if hit['event_type'] == 'Exploit':
            src_attr.add_tag('kill-chain:Exploitation')

    def handle_endlessh(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='SSH', disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_gopot(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='HTTP', disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_heralding(hit, src_attr, obj):
        src_attr.add_tag('misp-galaxy:mitre-attack-pattern="Brute Force - T1110"')
        src_attr.add_tag('kill-chain:Exploitation')
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value=hit['proto'].upper(), disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_honeypots(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value=hit['protocol'].upper().replace('_', ' '), disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)
        if hit['action'] == 'login':
            src_attr.add_tag('misp-galaxy:mitre-attack-pattern="Brute Force - T1110"')
            src_attr.add_tag('kill-chain:Exploitation')           
        if hit['action'] == 'connection':
            src_attr.add_tag('misp-galaxy:mitre-attack-pattern="Active Scanning - T1595"')
            src_attr.add_tag('kill-chain:Reconnaissance')

    def handle_honeyaml(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='HTTP', disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_ipphoney(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='IPP', disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_log4pot(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        port_protocols_log4pot = {
            80: 'HTTP',
            443: 'HTTPS',
            8080: 'HTTP',
            9200: 'ELASTICSEARCH',
            25565: 'HTTP'
        }
        if hit['dest_port'] in port_protocols_log4pot:
            obj.add_attribute('protocol', value=port_protocols_log4pot[hit['dest_port']], disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_mailoney(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='SMTP', disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_medpot(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='HL7', disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_miniprint(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='JETDIRECT', disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_redishoneypot(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='REDIS', disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_sentrypeer(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='SIP', disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_tanner(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        obj.add_attribute('protocol', value='HTTP', disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)

    def handle_wordpot(hit, src_attr, obj):
        src_attr.add_tag('honeypot-basic:interaction-level=low')
        if 'info' in hit and hit['info'] == 'enumeration':
            src_attr.add_tag('misp-galaxy:mitre-attack-pattern="Active Scanning - T1595"')
            src_attr.add_tag('kill-chain:Reconnaissance')
        elif 'username' in hit or 'password' in hit:
            src_attr.add_tag('misp-galaxy:mitre-attack-pattern="Brute Force - T1110"')
            src_attr.add_tag('kill-chain:Exploitation')
        obj.add_attribute('protocol', value='HTTP', disable_correlation=MISP_DISABLE_CORRELATION_PROTOCOL)
        

    HONEYPOT_HANDLERS = {
        'Suricata': handle_suricata,
        'Adbhoney': handle_adbhoney,
        'CitrixHoneypot': handle_citrixhoneypot,
        'Ciscoasa': handle_ciscoasa,
        'ConPot': handle_conpot,
        'Cowrie': handle_cowrie,
        'Ddospot': handle_ddospot,
        'Dicompot': handle_dicompot,
        'Dionaea': handle_dionaea,
        'ElasticPot': handle_elasticpot,
        'Endlessh': handle_endlessh,
        'Go-pot': handle_gopot,
        'Heralding': handle_heralding,
        'Honeypots': handle_honeypots,
        'Honeyaml': handle_honeyaml,
        'Ipphoney': handle_ipphoney,
        'Log4pot': handle_log4pot,
        'Mailoney': handle_mailoney,
        'Medpot': handle_medpot,
        'Miniprint': handle_miniprint,
        'Tanner': handle_tanner,
        'Redishoneypot': handle_redishoneypot,
        'Sentrypeer': handle_sentrypeer,
        'Wordpot': handle_wordpot
    }

    for bucket in all_buckets:
        hit = bucket['first_hit']['hits']['hits'][0]['_source']
        obj = MISPObject('network-traffic')
        comment = None
        if MISP_ENABLE_COMMENTS_IP:
            comment = ' | '.join(
                filter(
                    None,
                    [
                        hit.get('geoip', {}).get('country_name'),
                        f"ASN: {hit.get('geoip', {}).get('asn')}"
                        if hit.get('geoip', {}).get('asn')
                        else None,
                        hit.get('geoip', {}).get('as_org'),
                        hit.get('ip_rep'),
                    ],
                )
            ) or None

        src_attr = obj.add_attribute(
            'src_ip',
            value=hit['src_ip'],
            disable_correlation=MISP_DISABLE_CORRELATION_SRC_IP,
            comment=comment,
        )
        if hit.get('dest_port'): 
          dst_attr = obj.add_attribute('dst_port', value=hit['dest_port'], disable_correlation=MISP_DISABLE_CORRELATION_DST_PORT)
        
 
        
        obj.add_attribute('start_time', value=hit['@timestamp'], disable_correlation=MISP_DISABLE_CORRELATION_START_TIME)
        src_attr.add_tag('diamond-model:Infrastructure')  


        if MISP_ENABLE_COMMENTS_HONEYPOTS and hit['type'] != 'Suricata':
          obj.comment = f"First attack of {bucket['doc_count']} against {hit['type']}"


        handler = HONEYPOT_HANDLERS.get(hit['type'])
        if handler:
            handler(hit, src_attr, obj)        


        misp.add_object(evt, obj)


    publish_event = os.getenv('MISP_PUBLISH', 'true').lower() == 'true'

    if publish_event:
        misp.publish(eid)


    

