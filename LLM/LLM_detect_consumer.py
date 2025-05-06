import base64
import re
from urllib.parse import unquote_plus, urlparse
import torch
import sys
sys.path.append('.')
from core.inputter import HTTPDataset, RequestInfo
from LLM.LLM_task import LLM_task, Message
from transformers import AutoTokenizer, AutoModel, AutoModelForCausalLM
import argparse
import time
from lmdeploy import pipeline, TurbomindEngineConfig, GenerationConfig, ChatTemplateConfig
from tqdm import tqdm
import json
import os
from datetime import datetime
from LLM import data_analysis
from confluent_kafka import Consumer  # 新增Kafka依赖
import socket
import threading

# 新增Kafka配置
KAFKA_CONFIG = {
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'llm-detector',
    'auto.offset.reset': 'earliest'
}

parser = argparse.ArgumentParser()
parser.add_argument("--model", default="Qwen/Qwen2.5-7B-Instruct",
                    type=str, help="the model name of llm")
parser.add_argument("--result_dir", type=str, required=True, help="the path of result dir")
parser.add_argument('--gpu', default="0", type=str, help="Comma-separated list of GPU IDs, e.g., '0,2'")
# 获取指定的设备
args = parser.parse_args()
# 设置环境变量，让系统只看到这些 GPU
os.environ["CUDA_VISIBLE_DEVICES"] = args.gpu

args = parser.parse_args()

# 初始化全局组件
backend_config = TurbomindEngineConfig(cache_max_entry_count=0.2, tp=1)
gen_config = GenerationConfig(
    top_p=1.0,
    top_k=50,
    temperature=0.8,
    max_new_tokens=6000,
    do_sample=True
)

# 初始化向量数据库（与原代码相同）
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_community.vectorstores import Chroma
embeddings = SentenceTransformerEmbeddings(
    model_name="nomic-ai/nomic-embed-text-v1",
    model_kwargs={'device': 'cuda', 'trust_remote_code': True},
    encode_kwargs={'batch_size': 32}
)
vectorstore = Chroma(persist_directory="LLM/attack_vectoronly_nomic_chroma3", embedding_function=embeddings)

print(len(vectorstore))


def parse_custom_body(body: str):
    """
    针对非标准的 JSON-like 格式 {key:value, key:value, ...} 做拆分。
    这里只是一个示例，简单判断是否大括号包围，然后用逗号拆分。
    如果检测不到该特征，就直接返回整段 body 作为一个元素。
    """
    body = body.strip()
    # 如果形如：{serviceType:1,fileName:1.png,...}
    if body.startswith('{') and body.endswith('}'):
        # 去除首尾的大括号
        inner = body[1:-1].strip()
        # 按逗号拆分
        parts = inner.split(',')
        # 这里按逗号分完，每一小段一般是 key:value 形式
        # 如果你希望进一步把 key 和 value 分开做处理，也可以做二级拆分。
        # 这里选择把 "key:value" 视为一个语义单元。
        result = []
        for p in parts:
            p = p.strip()
            # 如果里面还有嵌套结构等，要更复杂的处理，也可以在这里加逻辑
            # 对 fileContent 这种很长的值，可以直接整段保留
            result.append(p)
        return result
    else:
        # 如果不是这种大括号包裹的形式，就直接返回
        return [body]


def process_body(body):
    """
    处理 body 数据，选择性解码 Unicode 转义序列。
    """
    def decode_unicode_escapes(text):
        """
        解码字符串中的 Unicode 转义序列（如 \u0438）。
        """
        def replace_unicode(match):
            try:
                # 提取 Unicode 码点（如 0438）
                code_point = match.group(1)
                # 将码点转换为字符
                return chr(int(code_point, 16))
            except:
                # 如果解码失败，返回原始内容
                return match.group(0)
        
        # 正则表达式匹配 \uXXXX 形式的 Unicode 转义序列
        unicode_pattern = re.compile(r'\\u([0-9a-fA-F]{4})')
        # 替换所有匹配的 Unicode 转义序列
        return unicode_pattern.sub(replace_unicode, text)

    # 检测是否包含 Unicode 转义序列
    if re.search(r'\\u[0-9a-fA-F]{4}', body):
        body = decode_unicode_escapes(body)
    return body

def parse_multipart_body(body):
    body = body.strip()
    parts = []
    lines = body.split('\r\n')
    boundary = None
    current_part = {}
    
    def parse_complex_params(param_str):
        params = []
        # 允许键值对中包含括号和等号（如攻击 payload）
        pattern = re.compile(r'([^=&]+)=([^&]*)')
        matches = pattern.findall(param_str)
        for k, v in matches:
            params.append(f"{k}={v}")
        # 处理未匹配的剩余部分（如无值的键）
        remaining = re.sub(pattern, '', param_str)
        if remaining:
            params.extend(remaining.split('&'))
        return params
    
    for line in lines:
        line = line.strip()
        # 识别 boundary
        if line.startswith('-----------------------------'):
            if not boundary:
                boundary = line  # 第一行是 boundary
            else:
                # 结束当前 part
                if current_part:
                    parts.append(current_part)
                current_part = {}
        elif line.startswith('Content-Disposition:'):
            # 解析 Content-Disposition 头
            disp = line[len('Content-Disposition:'):].strip()
            # 提取 name（允许带括号和特殊字符）
            name_match = re.search(r'name=(["\']?)(.*?)\1', disp)
            if name_match:
                name = unquote_plus(name_match.group(2))
                current_part['name'] = name
        elif line and 'content' not in current_part:
            # 解析内容部分（可能是混淆的参数）
            content = line
            # 进一步解析参数
            params = parse_complex_params(content)
            current_part['content'] = params
    
    # 提取所有参数
    body_list = []
    for part in parts:
        if 'content' in part:
            body_list.extend(part['content'])
    return body_list

def get_http_level_split(req: RequestInfo):
    parsed = urlparse(req.url)
    path_parts = parsed.path.split('/')

    def is_form_urlencoded(body):
        pattern = r'^[\w.%+]+=[\S]*'
        return bool(re.match(pattern, body))
    def is_multipart(body):
        stripped = body.strip()
        return stripped.startswith('-----------------------------')

    url_list = ['/' + part for part in path_parts if part]

    query_list = parsed.query.split('&')
    
    # 检查请求体是否为表单数据
    body = req.body.strip()
    body = process_body(body)
    if is_multipart(body):
        body_list = parse_multipart_body(body)
    elif is_form_urlencoded(body):
        body_list = body.split('&')
    elif body.startswith('{') and body.endswith('}'):
        body_list = parse_custom_body(body) 
    else:
        body_list=[]
    
    # 清理空的查询字符串
    if len(query_list) == 1 and query_list[0] == '':
        query_list = []
    
    # group = ['Method:', req.method] + ['URL:'] + url_list + (['?'] + query_list if query_list else []) + ['Body:'] + body_list
    group = [req.method] + url_list + (query_list if query_list else []) + body_list
    group = [item for item in group if item.strip()]
    return group


def char_tokenizer_with_http_level_alignment(req: RequestInfo):
    all_list = []
    alignment = []
    group = get_http_level_split(req)

    for p in group:
        # decoded_p = unquote_plus(p, encoding='utf-8', errors='replace')# 先对p进行解码
        decoded_p = p
        # 循环解码直到没有可以解码的字符
        while True:
            new_decoded_p = unquote_plus(decoded_p, encoding='utf-8', errors='replace')
            if new_decoded_p == decoded_p:
                break
            decoded_p = new_decoded_p

        p_list = list(decoded_p)
        all_list.extend(p_list)

        alignment.append([decoded_p, p_list])

    return all_list, alignment


def init_kafka_consumer():
    """初始化Kafka消费者"""
    consumer = Consumer(KAFKA_CONFIG)
    return consumer

def get_attack_type(final_response: str, id_to_label: dict) -> str:
    """
    从 LLM 的最终输出文本中解析出 Attack Type，
    逻辑参考 llm_analysis_single 的思路。
    """
    # 定义和 llm_analysis_single 中相同的特殊缩写
    special_cases = {
        "cross-site scripting": "xss",
        "remote code execution": "rce",
        "path traversal": "traversal",
        "xml injection": "xxe",
    }
    
    # 构建小写版本的标签字典
    id_label_lower = {k: v.lower() for k, v in id_to_label.items()}
    # 替换特殊情况
    for k, v in id_label_lower.items():
        if v in special_cases:
            id_label_lower[k] = special_cases[v]

    # 先做小写化，方便匹配
    predicted = final_response.lower()

    # 提取 "final classification" 或 "final answer:" 之后的部分
    if "final classification" in predicted:
        predicted = predicted.split("final classification", 1)[1].strip()
    elif "final answer:" in predicted:
        predicted = predicted.split("final answer:", 1)[1].strip()

    # 尝试在文本中匹配已知标签
    match_found = False
    pred_label = None
    for k, v in id_label_lower.items():
        # 假如预测文本里包含了完整标签或者标签原文的小写，就认为匹配
        if v in predicted or id_to_label[k].lower() in predicted:
            pred_label = k
            match_found = True
            break

    # 返回匹配到的 label，否则 "unknown"
    if match_found:
        return id_to_label[pred_label]
    else:
        return "unknown"

from confluent_kafka import TopicPartition
def get_consumer_lag(consumer, topic='hmm'):
    """获取所有分区的积压消息数量（修复版）"""
    try:
        # 获取topic的所有分区ID
        metadata = consumer.list_topics(topic)
        partitions = [
            TopicPartition(topic, p)  # 必须使用confluent_kafka.TopicPartition
            for p in metadata.topics[topic].partitions.keys()  # 注意这里用.keys()
        ]
        
        # 获取当前消费位移（需显式请求）
        committed = consumer.committed(partitions, timeout=1.0)
        
        # 获取最新位移（逐个分区查询）
        lag_data = []
        for tp in partitions:
            # 获取分区高低水位
            _, high = consumer.get_watermark_offsets(tp, timeout=1.0)
            # 获取当前提交的偏移量
            current_offset = committed[partitions.index(tp)].offset if committed[partitions.index(tp)] else -1
            # 计算积压
            lag = max(0, high - current_offset - 1) if current_offset >= 0 else 0
            lag_data.append({
                'topic': topic,
                'partition': tp.partition,
                'current_offset': current_offset,
                'latest_offset': high,
                'lag': lag,
                'timestamp': datetime.now().isoformat()
            })
        return lag_data
    except Exception as e:
        print(f"获取积压数据失败: {str(e)}")
        return []

def record_lag_periodically(consumer, lag_log_path):
    """定期每10秒记录一次消费积压状态"""
    while True:
        time.sleep(10)  # 每10秒记录一次
        lag_data = get_consumer_lag(consumer)  # 获取消费积压数据
        if lag_data:
            with open(lag_log_path, 'a') as f:
                for entry in lag_data:
                    f.write(json.dumps(entry) + '\n')

def process_single_request(req: RequestInfo, pipe, result_writer):
    """处理单个请求（原批量处理逻辑拆解）"""
    try:
        # 特征提取
        _, alignment = char_tokenizer_with_http_level_alignment(req)
        http_token = [part for part, _ in alignment]

        # 第一阶段LLM分析
        llm_input = [
            {"role": "system", "content": prompt_localization.strip()},
            {"role": "user", "content": str(http_token)}
        ]
        response = pipe([llm_input], gen_config=gen_config)[0]
        
        # 处理中间结果
        predicted_malicious = response.text.split("Final Answer:")[-1].strip()
        
        # 相似性搜索
        results_with_scores = vectorstore.similarity_search_with_score(predicted_malicious, 6)
        related_attack_info = [
            f"Related attack vector: {result[0].page_content[:1000]}, Category: {result[0].metadata.get('attack_category', 'Unknown')}"
            for result in results_with_scores
        ]
        
        if predicted_malicious != "":
            # 第二阶段LLM分析
            input_text = json.dumps({"method": req.method, "url": req.url, "body": req.body})
            final_input = prompt_analyse.format(
                input_text=input_text,
                malicious_part=predicted_malicious,
                retrive_attack_information="\n".join(related_attack_info)
            )
            
            # 执行最终分析
            idx = final_input.find("# Input request")
            system_content = final_input[:idx].strip()
            user_content = final_input[idx:].strip()
            final_response = pipe([[
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_content}
            ]], gen_config=gen_config)[0].text
            attack_type = get_attack_type(final_response, id_to_label)
        else:
            final_response = "normal"
            attack_type = "normal"

        # >>>>>>>>>>> 新增：提取 attack_type <<<<<<<<<<
        if attack_type.lower() not in ("normal", "unknown","others"):
            # 实时保存结果
            result = {
                "endtimestamp": datetime.now().isoformat(),
                "request_id": id(req),
                "raw_request": req.__dict__,
                "predicted_malicious": predicted_malicious,
                "final_analysis": final_response,
                "related_attacks": related_attack_info,
                "attack_type": attack_type
            }
            result_writer.write(json.dumps(result) + "\n")
            result_writer.flush()  # 确保实时写入

    except Exception as e:
        print(f"处理请求 {id(req)} 失败: {str(e)}")
        # 将错误信息写入独立日志
        with open(os.path.join(args.result_dir, "error.log"), "a") as f:
            f.write(f"{datetime.now().isoformat()} [ERROR] {str(e)}\n")

def realtime_processing_loop():
    """实时处理主循环"""
    # 初始化Kafka消费者
    consumer = init_kafka_consumer()
    consumer.subscribe(['hmm'])

    # 创建积压日志文件
    lag_log_path = os.path.join(args.result_dir, "consumer_lag.jsonl")
    # 启动记录积压的线程
    lag_thread = threading.Thread(target=record_lag_periodically, args=(consumer, lag_log_path), daemon=True)
    lag_thread.start()

    # 初始化模型管道
    pipe = pipeline(args.model, backend_config=backend_config)
    # 打开实时结果文件
    with open(os.path.join(args.result_dir, f"realtime_results_{args.gpu}.jsonl"), "w") as result_writer:
        try:
            while True:
                msg = consumer.poll(1.0)
                print(msg)

                if msg is None:
                    continue

                try:
                    # 反序列化请求
                    req = RequestInfo.deserialize(msg.value())
                    print(req)
                    process_single_request(req, pipe, result_writer)
                    consumer.commit(message=msg, asynchronous=False)
                except Exception as e:
                    print(f"消息处理失败: {str(e)}")
                    # 记录原始错误消息
                    with open(os.path.join(args.result_dir, "failed_messages.log"), "ab") as f:
                        f.write(msg.value() + b"\n")

        except KeyboardInterrupt:
            print("\n正在关闭...")
        finally:
            consumer.close()

if __name__ == "__main__":
    # 加载提示模板（与原代码相同）
    with open("LLM/Prompt/act_thought_analysetwostep.txt", 'r', encoding='utf-8') as file:
        prompt_analyse = file.read()
    with open("LLM/Prompt/act_thought_findmalicious.txt", 'r', encoding='utf-8') as file:
        prompt_localization = file.read()

    with open("LLM/Prompt/pdata.json", 'r', encoding='utf-8') as file:
        id_to_label = json.load(file)

    # 创建结果目录
    if not os.path.exists(args.result_dir):
        os.makedirs(args.result_dir)

    # 启动实时处理
    start_time = time.time()
    realtime_processing_loop()
    
    # 计算运行时间
    total_time = time.time() - start_time
    print(f"Total runtime: {total_time} seconds")

    # 注意：原data_analysis部分需要根据实时日志调整，此处保留但需要独立运行
    # data_analysis.llm_analysis_with_confusion_matrices(...)

