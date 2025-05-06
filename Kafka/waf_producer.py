import shlex
import sys
import os
import time
import argparse
from tqdm import tqdm
import torch
import random
import subprocess
import numpy as np
import w3lib.url
import warnings
import datetime  # 新增时间模块
# 忽略所有警告
warnings.filterwarnings("ignore")
sys.path.append('.')
from core.inputter import HTTPDataset
import json
from sklearn.metrics import accuracy_score, f1_score, classification_report
from urllib.parse import urlparse,quote, urlencode, parse_qs


# 新增 Kafka 依赖
from confluent_kafka import Producer
import socket
def init_kafka_producer():
    """初始化 Kafka 生产者"""
    conf = {
        'bootstrap.servers': 'localhost:9092',  # Kafka 服务器地址
        'client.id': socket.gethostname(),
        'message.send.max.retries': 3,          # 发送失败重试次数
        'acks': 'all'                           # 高可靠性模式
    }
    return Producer(conf)

# 在全局初始化 Kafka 生产者
kafka_producer = init_kafka_producer()

# def kafka_delivery_report(err, msg):
#     """发送消息的回调函数"""
#     if err is not None:
#         print(f'Kafka 消息发送失败: {err}')
#     else:
#         print(f'Kafka 消息已发送到 [{msg.topic()}] 分区 {msg.partition()}')


def load_datasets(test_path):
    with open(test_path, 'r') as file:
        test_data_json = [json.loads(line) for line in file]

    test_dataset = HTTPDataset.load_from(test_path)
    test_dataset.shuffle_dataset()
    test_Y = [req.label for req in test_dataset]
    test_labels = [0 if label == 0 else 1 for label in test_Y]  # No need for tensor

    return test_dataset, test_data_json, test_labels, test_Y

import json
from urllib.parse import quote
import http.client

import time

def test_with_firewall1(test_dataset, test_labels, tmp_dir, datasetname):
    # 新增代码：读取原始请求数据
    with open(args.test_path, 'r') as f:
        original_requests = [line.strip() for line in f]
    
    # 初始化结果文件路径
    output_path = os.path.join(tmp_dir, f"{datasetname}.jsonl")
    allowed_file = os.path.join(tmp_dir, f"{datasetname}_allowed.jsonl")
    denied_file = os.path.join(tmp_dir, f"{datasetname}_denied.jsonl")  # 新增被拦截请求文件
    
    # 清空已有结果文件（如果需要）
    for file_path in [output_path, allowed_file, denied_file]:
        if os.path.exists(file_path):
            os.remove(file_path)
    
    results = []
    firewall_results = []
    statuscode = []
    firewall_address = "http://localhost:8090"

    last_request_time = 0
    for index, (request_info, raw_line) in enumerate(zip(test_dataset, original_requests)):
        # 速率控制
        elapsed = time.time() - last_request_time
        if elapsed < MIN_INTERVAL:
            time.sleep(MIN_INTERVAL - elapsed)
        last_request_time = time.time()

        starttimestamp = datetime.datetime.now().isoformat()  # 统一时间戳
        
        method = request_info.method.upper()
        url = f"{firewall_address}{request_info.url}" if request_info.url.startswith('/') else f"{firewall_address}/{request_info.url}"
        url = w3lib.url.canonicalize_url(url)

        data = request_info.body if request_info.body else None
        headers = {}

        # Construct curl command
        curl_cmd = ['curl', '-i', '-X',method, url]
        if data:
            curl_cmd.extend(['-d', data])

        try:
            # Execute curl command and capture output
            result = subprocess.run(['curl', '-i', '-X', method, url] + (['-d', data] if data else []),
                                  capture_output=True, text=True, timeout=5)

            output = result.stdout
            
            status_code = None

            # Extract the HTTP status code from the output
            for line in output.splitlines():
                if line.startswith('HTTP/'):
                    status_code = int(line.split()[1])
                    break

            # Analyze the response
            if status_code == 200:
                firewall_results.append(0)  # Request allowed
                # 保存到allowed文件（带时间戳）
                allowed_record = json.loads(raw_line)
                allowed_record['starttimestamp'] = starttimestamp
                test_dataset[index].starttimestamp = starttimestamp
                with open(allowed_file, 'a') as f:
                    json.dump(allowed_record, f)
                    f.write('\n')
                # Kafka生产消息
                kafka_producer.produce(
                    topic='waf',
                    value=test_dataset[index].serialize()
                )
                kafka_producer.poll(0)
            elif status_code in [403]:
                firewall_results.append(1)  # Request blocked
                # 保存到denied文件（带时间戳）
                denied_record = json.loads(raw_line)
                denied_record.update({
                    'starttimestamp': starttimestamp,
                    'endtimestamp': datetime.datetime.now().isoformat(),
                    'status_code': status_code
                })
                with open(denied_file, 'a') as f:
                    json.dump(denied_record, f)
                    f.write('\n')
            else:
                firewall_results.append(test_labels[index])
                print("Unexpected status code:", status_code)
            
            statuscode.append(status_code)

        except subprocess.TimeoutExpired:
            firewall_results.append(-1)
            print(f"Request timed out for {url}")
            statuscode.append(None)
        except Exception as e:
            firewall_results.append(-1)
            print("Error executing request:", str(e))
            statuscode.append(None)

        # 构建完整结果记录（带时间戳）
        result_record = {
            'url': request_info.url,
            'method': method,
            'body': data,
            'headers': headers,
            'status_code': statuscode[-1],
            'firewall_label': firewall_results[-1],
            'true_label': test_labels[index]
        }
        
        # 实时保存到主结果文件
        with open(output_path, 'a') as outfile:
            json.dump(result_record, outfile)
            outfile.write('\n')
        
        results.append(result_record)

    # 保存匹配结果文件
    result_file = os.path.join(tmp_dir, f"{datasetname}_waf_matches.txt")
    with open(result_file, 'w') as f:
        for result in firewall_results:
            f.write(f"{int(result)}\n")
    print(f"\nWAF匹配结果已保存到: {result_file}")
    print(f"允许的请求已保存到: {allowed_file}")
    print(f"拦截的请求已保存到: {denied_file}")

    return firewall_results


def report(all_labels, all_predictions, n_class=2):
    target_names = [f'Class {i}' for i in range(n_class)]

    report_str = classification_report(
        all_labels, all_predictions, zero_division=0, labels=list(range(n_class)), target_names=target_names, digits=4
    )
    print(report_str)

    bin_all_labels = [1 if label > 0 else label for label in all_labels]
    bin_all_predictions = [1 if label > 0 else label for label in all_predictions]
    accuracy = accuracy_score(bin_all_labels, bin_all_predictions)
    print('Normal Accuracy: %.2f %%' % (100 * accuracy), '\n')
    return

# Parsing arguments
parser = argparse.ArgumentParser()
parser.add_argument('--test_path', type=str, required=True)
parser.add_argument('--tmp_dir', type=str, required=True)
parser.add_argument('--datasetname', type=str, required=True)
parser.add_argument('--persecond', type=int, required=True)
args = parser.parse_args()
# 在 test_with_firewall1 函数开头添加
REQUEST_RATE = args.persecond
MIN_INTERVAL = 1.0 / REQUEST_RATE

# Load data and prepare for testing
test_dataset, test_data_json, test_labels, test_Y = load_datasets(args.test_path)
test_dataset.shuffle_dataset()
firewall_results = test_with_firewall1(test_dataset, test_labels, args.tmp_dir, args.datasetname)
report(test_labels, firewall_results, 2)

# testpath是测试数据的路径，tmpdir是保存结果文件的目录，datasetname是数据集的名字。案例如下：
# python -u Kafka/waf_producer.py --test_path tmp_dir/pdata/test.jsonl --datasetname pdata --tmp_dir test_waf_after &> test_waf_after/pdata.log &
