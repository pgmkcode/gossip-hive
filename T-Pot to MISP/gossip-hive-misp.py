from pymisp import PyMISP, MISPEvent, MISPObject  
from datetime import datetime, timedelta,timezone
from elasticsearch import Elasticsearch
import json, logging, urllib3, os, argparse
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


filepath = '/tmp/date_time_limit_range.txt'
datetime_limit_range_str = read_last_timestamp(filepath)

low_limit_range = datetime_limit_range_str if datetime_limit_range_str else f"now-{args.minutes}m"
if not datetime_limit_range_str:
    print(f"No previous timestamp found; will be used 'now-{args.minutes}m'")

high_limit_range = now_utc.strftime('%Y-%m-%dT%H:%M:%S.000Z') 

save_last_timestamp(filepath, high_limit_range)

load_dotenv()
dest_ports_str = os.getenv('DEST_PORT', '22,80,110,143,443,465,993,995,1080,5432,5900')
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
              "lte":  high_limit_range
            }
          }
        },
     
        {
          "terms": {
            "type.keyword": ["Suricata","Heralding"]
          }
        },
          {
          "terms": {
            "dest_port": dest_ports
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
          { "dest_port": { "terms": { "field": "dest_port"        } } }
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
            ]
            ,
            "_source": [    "@timestamp",    "src_ip",    "dest_port",    "type",    "event_type",    "alert.signature"  ]
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




es = Elasticsearch(os.getenv('ELASTICSEARCH_URL'))
MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")
MISP_VERIFY_CERT = os.getenv("MISP_VERIFY_CERT", "False").lower() == "true"

ts_file = '/tmp/last_datetime_event.txt'
last_ts = read_last_timestamp(ts_file)

evt_time_str = now_local.strftime('%Y-%m-%d %H:%M')



all_buckets = []

resp = search_logs(es,log_today,query)

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
        'PAP:GREEN',
        'tlp:green',
        'honeypot-basic:communication-interface=network-interface',
        'honeypot-basic:data-capture=attacks',
        'honeypot-basic:interaction-level=low',
        'misp-galaxy:mitre-d3fend="Decoy Network Resource"',
        'misp-galaxy:mitre-d3fend="Standalone Honeynet"'
    ]:
        misp.tag(evt, tag)

    for bucket in all_buckets:
        hit = bucket['first_hit']['hits']['hits'][0]['_source']
        obj = MISPObject('network-traffic')
        src_attr = obj.add_attribute('src_ip', value=hit['src_ip'])
        dst_attr = obj.add_attribute('dst_port', value=hit['dest_port'])
        obj.comment = f"Source: {hit['type']}; Timestamp: {hit['@timestamp']}"

        

        if hit.get('event_type') == 'alert' and 'alert' in hit:
            sig = hit['alert'].get('signature', 'unknown')
            obj.comment += f"; Alert - Signature: {sig}"
            
        src_attr.add_tag('diamond-model:Infrastructure')

        if hit['type'] == 'Heralding':
            src_attr.add_tag('misp-galaxy:mitre-attack-pattern="Brute Force - T1110"')
            src_attr.add_tag('kill-chain:Exploitation')
        if hit['type'] == 'Suricata' and hit.get('event_type') != 'alert':
            src_attr.add_tag('misp-galaxy:mitre-attack-pattern="Active Scanning - T1595"')
            src_attr.add_tag('kill-chain:Reconnaissance')
    
        misp.add_object(evt, obj)

    publish_event = os.getenv('MISP_PUBLISH', 'true').lower() == 'true'

    if publish_event:
        misp.publish(eid)

