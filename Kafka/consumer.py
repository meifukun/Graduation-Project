from confluent_kafka import Consumer

conf = {
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'test-group',
    'auto.offset.reset': 'earliest'
}

consumer = Consumer(conf)
consumer.subscribe(['test-topic'])

try:
    while True:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        print(f"收到消息: Key={msg.key()}, Value={msg.value()}")
except KeyboardInterrupt:
    pass
finally:
    consumer.close()