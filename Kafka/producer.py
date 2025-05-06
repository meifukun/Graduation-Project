from confluent_kafka import Producer

conf = {'bootstrap.servers': 'localhost:9092'}
producer = Producer(conf)

for i in range(3):
    producer.produce('test-topic', key=str(i), value=f'Message {i}')
    producer.poll(0)

producer.flush()
print("消息发送完成！")