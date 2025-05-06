1、启动zookeeper
docker run -d \
  --name zookeeper \
  -p 2181:2181 \
  -e ZOOKEEPER_CLIENT_PORT=2181 \
  -e ALLOW_ANONYMOUS_LOGIN=yes \
  confluentinc/cp-zookeeper:latest

2、启动kafka
docker run -d \
  --name kafka \
  -p 9092:9092 \
  -e KAFKA_BROKER_ID=1 \
  -e KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181 \
  -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:9092 \
  -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
  --link zookeeper \
  confluentinc/cp-kafka:latest

3、测试
创建topic
docker exec -it kafka bash 
[appuser@37f3a0746dbd ~]$ kafka-topics --create \
--topic test-topic \
--bootstrap-server localhost:9092 \
--partitions 1 \
--replication-factor 1

kafka-topics --bootstrap-server localhost:9092 --delete --topic test-topic


4、完整测试流程
docker exec -it kafka bash 

kafka-topics --create \
--topic hmm \
--bootstrap-server localhost:9092 \
--partitions 1 \
--replication-factor 1

kafka-topics --create \
--topic waf \
--bootstrap-server localhost:9092 \
--partitions 1 \
--replication-factor 1

python LLM/LLM_detect_consumer.py --result_dir realtime_test --gpu 0

python Kafka/hmm_producer_consumer.py

开防火墙

python  Kafka/waf_producer.py --test_path tmp_dir/pdata-ood/test.jsonl --datasetname pdata-ood --tmp_dir realtime_test --persecond 3

python ui/ui_realtime.py