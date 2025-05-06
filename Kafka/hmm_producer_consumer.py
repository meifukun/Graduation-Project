import json
import os
import math
from urllib.parse import urlparse, parse_qs, unquote
from joblib import load
import numpy as np
import sys
sys.path.append('.')
from core.inputter import RequestInfo  # 根据实际路径调整

# 超参数配置
HMM_CONFIG = {
    'n_components': 4,    # 隐状态数量
    'n_iter': 100,        # 最大迭代次数
    'prob_threshold': 0.1 # 异常概率阈值
}

# 新增 Kafka 依赖
from confluent_kafka import Consumer, Producer
import socket

# 初始化 Kafka 生产者（用于发送到 hmm topic）
def init_kafka_producer():
    conf = {
        'bootstrap.servers': 'localhost:9092',
        'client.id': socket.gethostname(),
        'message.send.max.retries': 3,
        'acks': 'all'
    }
    return Producer(conf)

hmm_producer = init_kafka_producer()

# 初始化 Kafka 消费者（用于读取 waf topic）
def init_kafka_consumer():
    conf = {
        'bootstrap.servers': 'localhost:9092',
        'group.id': 'hmm-detector',
        'auto.offset.reset': 'earliest'
    }
    return Consumer(conf)

def create_identifier(request):
    """根据请求结构生成唯一标识符"""
    method = request['method'].upper()
    path = urlparse(request['url']).path.lower()
    
    # 解析查询参数
    query_params = parse_qs(urlparse(request['url']).query)
    sorted_query = sorted(query_params.keys())
    
    # 解析body参数（支持表单和JSON格式）
    body_params = {}
    if request['body']:
        body_params = parse_qs(request['body'])
    
    sorted_body = sorted(body_params.keys())
    
    # 构建标识符
    # 去掉前后的斜杠并替换斜杠为下划线
    path = path.strip('/').replace('/', '_')
    if method == 'GET':
        return f"{method}|{path}|{'_'.join(sorted_query)}"
    else:
        return f"{method}|{path}|{'_'.join(sorted_body)}"


def encode_value(value):
    """参数值编码规则"""
    return ''.join(
        'A' if c.isalpha() else 
        'N' if c.isdigit() else 
        'S' for c in str(value)
    )

# 新增标识符编解码函数
def encode_identifier(identifier):
    """将标识符转换为安全文件名"""
    return identifier.replace("|", "__PIPE__").replace("/", "__SLASH__")

def decode_identifier(filename):
    """从文件名恢复原始标识符""" 
    return filename.replace("__PIPE__", "|").replace("__SLASH__", "/")

def load_models(model_dir):
    """加载所有HMM模型"""
    models = {}
    for fname in os.listdir(model_dir):
        if fname.endswith(".joblib"):
            # 分割文件名：identifier_part__param.joblib
            parts = fname.rsplit("__", 1)  # 从右边只分割一次
            
            # 解码标识符
            identifier_part = parts[0]
            identifier = decode_identifier(identifier_part).replace("___", "|").replace("__", "|")
            # 解析参数名
            param_part = parts[1].replace(".joblib", "")
            
            # 加载模型
            models.setdefault(identifier, {})[param_part] = load(
                os.path.join(model_dir, fname)
            )

    return models

from confluent_kafka import TopicPartition
# def get_partition_with_least_lag(topic, bootstrap_servers='localhost:9092'):
#     """获取积压最少的分区ID"""
#     # 创建一个临时消费者来查询分区状态
#     consumer_conf = {
#         'bootstrap.servers': bootstrap_servers,
#         'group.id': 'temp-lag-checker',
#         'auto.offset.reset': 'earliest'
#     }
#     consumer = Consumer(consumer_conf)
    
#     try:
#         min_lag = float('inf')
#         min_lag_partition = 0
#         # 获取topic的所有分区ID
#         metadata = consumer.list_topics(topic)
#         partitions = [
#             TopicPartition(topic, p)  # 必须使用confluent_kafka.TopicPartition
#             for p in metadata.topics[topic].partitions.keys()  # 注意这里用.keys()
#         ]
        
#         # 获取当前消费位移（需显式请求）
#         committed = consumer.committed(partitions, timeout=1.0)
        
#         # 获取最新位移（逐个分区查询）
#         for tp in partitions:
#             # 获取分区高低水位
#             _, high = consumer.get_watermark_offsets(tp, timeout=1.0)
#             # 获取当前提交的偏移量
#             current_offset = committed[partitions.index(tp)].offset if committed[partitions.index(tp)] else -1
#             # 计算积压
#             lag = max(0, high - current_offset - 1) if current_offset >= 0 else 0
#             print(lag)
#             if lag < min_lag:
#                 min_lag = lag
#                 min_lag_partition = tp.partition
        
#         return min_lag_partition
#     finally:
#         consumer.close()


def get_partition_with_least_lag(topic, bootstrap_servers='localhost:9092'):
    """获取积压最少的分区ID"""
    # 创建一个临时消费者来查询分区状态
    consumer_conf = {
        'bootstrap.servers': bootstrap_servers,
        'group.id': 'llm-detector',
        'auto.offset.reset': 'earliest'
    }
    consumer = Consumer(consumer_conf)
    
    try:
        # 获取topic的所有分区
        metadata = consumer.list_topics(topic)
        partitions = [
            TopicPartition(topic, p)  # 必须使用confluent_kafka.TopicPartition
            for p in metadata.topics[topic].partitions.keys()  # 注意这里用.keys()
        ]
        
        min_lag_partition = 0
        min_lag = float('inf')
        committed = consumer.committed(partitions, timeout=1.0)
        for tp in partitions:
            # 获取分区高低水位
            _, high = consumer.get_watermark_offsets(tp, timeout=1.0)
            # 获取当前提交的偏移量
            current_offset = committed[partitions.index(tp)].offset if committed[partitions.index(tp)] else -1
            # 计算积压
            lag = max(0, high - current_offset - 1) if current_offset >= 0 else 0
            print(lag)
            if lag < min_lag:
                min_lag = lag
                min_lag_partition = tp.partition
        print(min_lag_partition)
        return min_lag_partition
    finally:
        consumer.close()

def detect_anomalies(kafka_topic, models, result_file, attack_file):

    """从 Kafka 消费数据执行检测"""
    consumer = init_kafka_consumer()
    consumer.subscribe([kafka_topic])

    # 打印所有模型的键（标识符）
    print("Models Keys:")
    for identifier in models.keys():
        print(identifier)
    """执行异常检测"""
    stats = {
        'total': 0,
        'true_positive': 0,
        'false_positive': 0,
        'unknown_structure': 0,
        'true_negative': 0,
        'false_negative': 0,
    }

    with open(result_file, 'w') as fout, \
         open(attack_file, 'w') as fattack:  # 新增攻击记录文件
        try:
            while True:
                msg = consumer.poll(1.0)
                print(msg)
                if msg is None:
                    continue
                if msg.error():
                    print(f"消费者错误: {msg.error()}")
                    continue

                try:
                    # 反序列化请求（假设使用 RequestInfo 类）
                    req_obj = RequestInfo.deserialize(msg.value())
                    req = json.loads(req_obj.dump_json())  # 转为字典格式
                except Exception as e:
                    print(f"反序列化失败: {str(e)}")
                    continue

                stats['total'] += 1
            
                # 生成请求标识符
                identifier = create_identifier(req)
                # print(identifier)
                # 未知结构处理
                if identifier not in models.keys():
                    stats['unknown_structure'] += 1
                    fout.write(json.dumps({
                        **req,
                        "prediction": "unknown_structure"
                    }) + "\n")

                    is_attack = req['label'] != 0 # 根据实际标签定义
                    if is_attack:
                        stats['true_positive'] += 1
                    else:
                        stats['false_positive'] += 1
                    
                    # 发送原始字节数据到 hmm topic
                    partition = get_partition_with_least_lag('hmm')
                    hmm_producer.produce(
                        topic='hmm',
                        value=msg.value(),  # 直接转发原始字节
                        partition=partition  # 选择当前分区
                    )
                    hmm_producer.poll(0)

                    # 同时写入本地文件
                    fattack.write(json.dumps(req) + "\n")

                    continue

                # 参数异常检测
                anomaly_params = []
                model_params = models[identifier]
                
                # 收集所有参数值
                param_values = {}
                # 解析查询参数
                query_params = parse_qs(urlparse(req['url']).query)
                for p, v in query_params.items():
                    param_values.setdefault(p, []).extend(v)
                # 解析body参数
                if req['body']:
                    try:
                        body_params = parse_qs(req['body'])
                        for p, v in body_params.items():
                            param_values.setdefault(p, []).extend(v)
                    except:
                        pass
                
                # 对每个参数进行检测
                for param, values in param_values.items():
                    if param not in model_params:
                        continue
                    
                    model = model_params[param]
                    for val in values:
                        try:
                            encoded = [ord(c) for c in encode_value(val)]
                            seq = np.array(encoded).reshape(-1, 1)
                            log_prob = model.score(seq)
                            prob = 1 / (1 + math.exp(-log_prob))
                            
                            if prob < HMM_CONFIG['prob_threshold']:
                                anomaly_params.append(param)
                                break  # 发现异常即停止检测
                        except:
                            pass
                
                # 结果记录
                is_attack = req['label'] != 0 # 根据实际标签定义
                result = {
                    "original": req,
                    "anomaly_params": anomaly_params,
                    "is_attack": is_attack
                }
                
                # 更新统计
                if len(anomaly_params) > 0:
                    # 发送原始字节数据到 hmm topic
                    partition = get_partition_with_least_lag('hmm')
                    hmm_producer.produce(
                        topic='hmm',
                        value=msg.value(),  # 直接转发原始字节
                        partition=partition
                        # key=msg.key()
                    )
                    hmm_producer.poll(0)

                    # 同时写入本地文件
                    fattack.write(json.dumps(req) + "\n")

                    if is_attack:
                        stats['true_positive'] += 1
                    else:
                        stats['false_positive'] += 1
                elif len(anomaly_params) == 0:
                    if is_attack:
                        stats['false_negative'] += 1
                        result = {
                            "original": req,
                            "anomaly_params": anomaly_params,
                            "is_attack": is_attack,
                            "false_negative": True
                        }
                    else:
                        stats['true_negative'] += 1
                
                fout.write(json.dumps(result) + "\n")
    
        except KeyboardInterrupt:
            pass
        finally:
            consumer.close()
            hmm_producer.flush()

            print("检测结果统计:")
            print(f"总请求数: {stats['total']}")
            print(f"未知结构请求: {stats['unknown_structure']}")
            print(f"正确检测攻击: {stats['true_positive']}")
            print(f"误报数: {stats['false_positive']}")
            print(f"正确检测正常: {stats['true_negative']}")
            print(f"漏报数: {stats['false_negative']}")

if __name__ == "__main__":
    models = load_models("hmm_model")
    # detect_anomalies(
    #     kafka_topic='waf',
    #     models=models,
    #     result_file="realtime_test/detection_results.jsonl",
    #     attack_file="realtime_test/malicious_requests.jsonl",
    #     partition=3
    # )
    # detect_anomalies(
    #     kafka_topic='waf',
    #     models=models,
    #     result_file="realtime_oodtest1/detection_results.jsonl",
    #     attack_file="realtime_oodtest1/malicious_requests.jsonl"
    # )
    # detect_anomalies(
    #     kafka_topic='waf',
    #     models=models,
    #     result_file="realtime_oodtest11/detection_results.jsonl",
    #     attack_file="realtime_oodtest11/malicious_requests.jsonl"
    # )
    detect_anomalies(
        kafka_topic='waf',
        models=models,
        result_file="realtime_iidtest1/detection_results.jsonl",
        attack_file="realtime_iidtest1/malicious_requests.jsonl"
    )
