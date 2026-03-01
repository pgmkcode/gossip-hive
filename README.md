# Gossip-Hive
T-Pot as a source of Cyber Threat Intelligence

## Introduction
Gossip-Hive originated as a project idea developed during my postgraduate studies in Networks and Security, while I was working at [LINTI](https://www.linti.unlp.edu.ar/) (Laboratorio de Investigación en Nuevas Tecnologías Informáticas) at [UNLP](https://unlp.edu.ar/) (Universidad Nacional de La Plata). During that period, I presented the research progress at various conferences and workshops. Final document at [SEDICI](https://sedici.unlp.edu.ar/handle/10915/190822)

Upon completing the postgraduate program (final GPA: 9.33), I have continued to maintain and further develop the project in my spare time.


## How does Gossip Hive for MISP work?
Gossip Hive collects attacks received by T-Pot at a set frequency. The ports where the attacks are received and the IP addresses to be excluded are established (it's recommended to exclude T-Pot's own address). When attacks are reported to MISP, an event is created with the corresponding taxonomies and galaxies, and certain objects of the received attacks are tagged.

## Gossip-Hive for MISP requirements
* MISP
* T-Pot

## Gossip-Hive features
- Automatic tags (Galaxies and Taxonomies)
- Correlation options
- Destination port, protocol, and date/time of the first attack
- Suricata alerts and signatures
- Attack count
- IP address information (country, ASN name, ASN number, and reputation)

### T-Pot steps
* Expose the ElasticSearch port from T-Pot (to remember even every time a _custom-docker-compose.yml_ is generated)
```
sed -i 's|127.0.0.1:64298:9200|0.0.0.0:64298:9200|' ~/tpotce/docker-compose.yml
```
* Get the Elasticsearch API URL and set it at .env 
```
ELASTICSEARCH_URL
```
* Exclude T-Pot IP address 
```
EXCLUDED_SRC_IPS
```

### MISP steps
* Get the MISP API KEY and set it at .env
```
MISP_KEY
```
* Get the MISP API URL and set it at .env 
```
MISP_URL
```
* Check other parameters if needed

### Gossip-Hive steps
```
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv gossip-hive
source gossip-hive/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python3 gossip-hive-misp.py
```

### Gossip-Hive frequency
```
python3 gossip-hive-misp.py --minutes=15
```
Default frequency is 60 minutes. 
* Configure a cron job to execute it with the same time parameter.

### Compatible honeypots from T-Pot
- Adbhoney
- CitrixHoneypot
- Ciscoasa
- ConPot
- Cowrie
- Ddospot
- Dicompot
- Dionaea
- ElasticPot
- Endlessh
- Go-pot
- Heralding
- Honeypots
- Honeyaml
- Ipphoney
- Log4pot
- Mailoney
- Medpot
- Miniprint
- Tanner
- Redishoneypot
- Sentrypeer
- Wordpot

### Galaxies and taxonomies used in MISP
- TLP
- PAP
- cssa:sharing-class
- cssa:origin
- admiralty-scale:source-reliability
- misp-galaxy:mitre-d3fend
- misp-galaxy:mitre-attack-pattern
- honeypot-basic:communication-interface
- honeypot-basic:data-capture
- honeypot-basic:interaction-level
- diamond-model:Infrastructure
- kill-chain:Exploitation
- kill-chain:Reconnaissance

### Licenses
GPLv2: [conpot](https://github.com/mushorg/conpot/blob/master/LICENSE.txt), [galah](https://github.com/0x4D31/galah?tab=Apache-2.0-1-ov-file#readme), [dionaea](https://github.com/DinoTools/dionaea/blob/master/LICENSE), [honeytrap](https://github.com/armedpot/honeytrap/blob/master/LICENSE), [suricata](https://suricata.io/features/open-source/)
GPLv3: [T-Pot](https://github.com/telekom-security/tpotce?tab=GPL-3.0-1-ov-file#readme), [adbhoney](https://github.com/huuck/ADBHoney), [elasticpot](https://gitlab.com/bontchev/elasticpot/-/blob/master/LICENSE), [ewsposter](https://github.com/telekom-security/ewsposter), [log4pot](https://github.com/thomaspatzke/Log4Pot/blob/master/LICENSE), [fatt](https://github.com/0x4D31/fatt/blob/master/LICENSE), [heralding](https://github.com/johnnykv/heralding/blob/master/LICENSE.txt), [ipphoney](https://gitlab.com/bontchev/ipphoney/-/blob/master/LICENSE), [miniprint](https://github.com/sa7mon/miniprint?tab=GPL-3.0-1-ov-file#readme), [redishoneypot](https://github.com/cypwnpwnsocute/RedisHoneyPot/blob/main/LICENSE), [sentrypeer](https://github.com/SentryPeer/SentryPeer/blob/main/LICENSE.GPL-3.0-only), [snare](https://github.com/mushorg/snare/blob/master/LICENSE), [tanner](https://github.com/mushorg/snare/blob/master/LICENSE)
Apache 2 License: [cyberchef](https://github.com/gchq/CyberChef/blob/master/LICENSE), [dicompot](https://github.com/nsmfoo/dicompot/blob/master/LICENSE), [elasticsearch](https://github.com/elasticsearch/elasticsearch/blob/master/LICENSE.txt), [go-pot](https://github.com/ryanolee/go-pot?tab=License-1-ov-file#readme), [h0neytr4p](https://github.com/pbssubhash/h0neytr4p?tab=Apache-2.0-1-ov-file#readme), [logstash](https://github.com/elasticsearch/logstash/blob/master/LICENSE.txt), [kibana](https://github.com/elasticsearch/kibana/blob/master/LICENSE.txt), [docker](https://github.com/docker/docker/blob/master/LICENSE)
MIT license: [autoheal](https://github.com/willfarrell/docker-autoheal?tab=MIT-1-ov-file#readme), [beelzebub](https://github.com/mariocandela/beelzebub?tab=MIT-1-ov-file#readme), [ciscoasa](https://github.com/Cymmetria/ciscoasa_honeypot/blob/master/LICENSE), [ddospot](https://github.com/aelth/ddospot/blob/master/LICENSE), [elasticvue](https://github.com/cars10/elasticvue/blob/master/LICENSE), [glutton](https://github.com/mushorg/glutton/blob/master/LICENSE), [hellpot](https://github.com/yunginnanet/HellPot/blob/master/LICENSE), [honeyaml](https://github.com/mmta/honeyaml?tab=MIT-1-ov-file#readme), [maltrail](https://github.com/stamparm/maltrail/blob/master/LICENSE)
Unlicense: [endlessh](https://github.com/skeeto/endlessh/blob/master/UNLICENSE)
Other: [citrixhoneypot](https://github.com/MalwareTech/CitrixHoneypot#licencing-agreement-malwaretech-public-licence), [cowrie](https://github.com/cowrie/cowrie/blob/master/LICENSE.rst), [mailoney](https://github.com/awhitehatter/mailoney), [Elastic License](https://www.elastic.co/licensing/elastic-license), [Wordpot](https://github.com/gbrindisi/wordpot)
AGPL-3.0: [MISP](https://github.com/MISP/MISP?tab=AGPL-3.0-1-ov-file#readme) [honeypots](https://github.com/qeeqbox/honeypots/blob/main/LICENSE) [IntelOwl](https://github.com/intelowlproject/IntelOwl?tab=AGPL-3.0-1-ov-file#readme)
[Public Domain (CC)](https://creativecommons.org/publicdomain/zero/1.0/): [Harvard Dataverse](https://dataverse.harvard.edu/dataverse/harvard/?q=dicom)



