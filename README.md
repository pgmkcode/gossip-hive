# gossip-hive
T-Pot as a source of Cyber Threat Intelligence

## Requirements for MISP
* MISP
* Exposed ElasticSearch port from T-Pot
* Debian 12 (tested)
* Install Python dot-env and activate 
* Install requirements.txt
* Assign environment variables (check .env file)

#How does Gossip Hive work for MISP?
Gossip Hive collects attacks received by T-Pot at a set frequency. The ports where the attacks are received and the IP addresses to be excluded are established (it's recommended to exclude T-Pot's own address). When attacks are reported to MISP, an event is created with the corresponding taxonomies and galaxies, and certain objects of the received attacks are tagged.

## Requirements for IntelOwl Analyzer
* IntelOwl
* Exposed ElasticSearch port from T-Pot

#How does Gossip Hive work for IntelOwl?
Simply look for the last attack received for a given IP address.
