# Kafka mirror maker lab

## Active/Passive

```
./run-kakfa-mirror-maker.sh
cd kafka/bin/
./connect-mirror-maker.sh mm2.properties
```


## Active to Active
```
./run-kakfa-mirror-maker.sh
cd kafka/bin/
./connect-mirror-maker.sh /data/active-to-active-mm2.properties
```

```
./kafka-topics.sh --zookeeper zookeeper-source:2181 --create --partitions 1 --replication-factor 1 --topic topic_1
./kafka-topics.sh --zookeeper zookeeper-target:2181 --create --partitions 1 --replication-factor 1 --topic topic_2
./kafka-topics.sh --zookeeper zookeeper-source:2181 --list
```


## validate

```
./kafka-topics.sh --zookeeper zookeeper-source:2181 --create --partitions 1 --replication-factor 1 --topic topic_1 --config cleanup.policy=delete

./kafka-topics.sh --zookeeper zookeeper-source:2181 --create --partitions 2 --replication-factor 1 --topic topic_2 --config cleanup.policy=delete

./kafka-topics.sh --zookeeper zookeeper-source:2181 --create --partitions 5 --replication-factor 1 --topic compact_3 --config cleanup.policy=delete

./kafka-topics.sh --zookeeper zookeeper-source:2181 --create --partitions 1 --replication-factor 1 --topic compacted_topic_1 --config cleanup.policy=compact

./kafka-topics.sh --zookeeper zookeeper-source:2181 --create --partitions 1 --replication-factor 1 --topic compacted_topic_2 --config cleanup.policy=compact
```


## docker 

```
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' source_kafka_ip
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' destination_kafka_ip
```
