
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
from openai import OpenAI
from openai import OpenAIError
import json
import os
from datetime import datetime
from LLM import data_analysis
import random
import concurrent.futures
parser = argparse.ArgumentParser()

parser.add_argument("--model", default="LLM-Research/Meta-Llama-3-8B-Instruct",
                    type=str, help="the model name of llm")
# Qwen/Qwen2.5-7B-Instruct
# /data1/lipeiyang/LLaMA-Factory/models/Qwen2_5-7b_lora_sft_attack_cls_v0_50_batch8_epoch6_lora_sft_loc_cls_cotdata_v1_1000_batch8_epoch10
parser.add_argument("--result_dir", type=str, required=True, help="the path of result dir")
parser.add_argument('--test_path', default="hmm/detection_results.jsonl",type=str)
parser.add_argument('--gpu', default="0", type=str, help="Comma-separated list of GPU IDs, e.g., '0,2'")
# 获取指定的设备
args = parser.parse_args()
# 设置环境变量，让系统只看到这些 GPU
os.environ["CUDA_VISIBLE_DEVICES"] = args.gpu


def load_datasets(test_path, device):
    # Load JSON lines as Python dictionaries
    with open(test_path, 'r') as file:
        test_data_json = [json.loads(line) for line in file]

    # Load HTTP dataset
    test_dataset = HTTPDataset.load_from(test_path)
    
    # Extract labels and convert to tensor
    test_Y = [req.label for req in test_dataset]
    test_labels = torch.tensor(test_Y, device=device)

    return test_dataset, test_data_json, test_labels, test_Y

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


backend_config = TurbomindEngineConfig(cache_max_entry_count=0.2, tp=1)
gen_config = GenerationConfig(top_p=1.0,
                              top_k=50,
                              temperature=0.8,
                              max_new_tokens=6000,
                              do_sample=True)

test_dataset, test_data_json, test_cls_ground_truth, _ = load_datasets(args.test_path, "cpu")
tokenizer = char_tokenizer_with_http_level_alignment

# v1只有三个类别
with open("LLM/Prompt/act_thought_analysetwostep.txt", 'r', encoding='utf-8') as file:
    prompt_analyse = file.read()

with open("LLM/Prompt/act_thought_findmalicious.txt", 'r', encoding='utf-8') as file:
    prompt_localization = file.read()

from langchain_community.embeddings import OpenAIEmbeddings
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_community.vectorstores import Chroma

embeddings = SentenceTransformerEmbeddings(
        model_name="nomic-ai/nomic-embed-text-v1",
        model_kwargs={'device': 'cuda', 'trust_remote_code': True},
        encode_kwargs={'batch_size': 32}
    )
vectorstore = Chroma(persist_directory="LLM/attack_vectoronly_nomic_chroma3", embedding_function=embeddings)

print(len(vectorstore))

def prepare_task(test_dataset, prompt, model_name, max_tokens):
    """基于测试数据集构建LLM任务队列"""
    task = []
    task_id = 1
    
    for req in test_dataset:
        # 构造请求数据结构
        request_data = json.dumps(
            {"method": req.method, "url": req.url, "body": req.body}
        )
        
        # 构建消息结构
        request = {
            "system": prompt.strip(),
            "user": request_data
        }
        
        # 元数据配置
        metadata = {
            "max_tokens": max_tokens,
            "temperature": 0.8,
            "top_p": 1.0
        }
        
        # 创建消息对象（使用lmdeploy引擎）
        message = Message(
            str(task_id),
            "lmdeploy",  # 引擎类型
            model_name,  # 模型名称
            request,
            metadata
        )
        message.dump_label(req.label)
        task.append(message)
        task_id += 1
    
    return LLM_task(task)

def generate_inputs(pipe):
    inputs = []

    # 在需要的位置调用该函数
    task = prepare_task(
        test_dataset=test_dataset,
        prompt=prompt_localization,  # 来自之前的prompt定义
        model_name=args.model,
        max_tokens=6000,  # 根据模型上下文长度调整
    )

    for data in task:
        taskid = data.id
        # taskid是字符串形式的，转成int形式的
        i = int(taskid) - 1

        # 检查一下data的label和那个test dataset对应条目的label是否一致，应该都是一致的
        assert data.label == test_dataset[i].label, f"Mismatch in labels for task ID {taskid}"

        _, alignment = tokenizer(test_dataset[i])
        http_token = [part for part, _ in alignment]  # http_token 是一个列表

        # location_ground_truth = get_location_ground_truth(dataset_name, test_data_json[i], http_token)
        
        # 拼成 Chat 格式
        message = [
            {"role": "system", "content": prompt_localization.strip()},
            {"role": "user", "content": str(http_token)}
        ]
        inputs.append(message)

    print(inputs[0])

    responses = pipe(inputs, gen_config=gen_config, use_tqdm=True)

    for response, data in zip(responses, task):
        # 预处理并生成中间结果
        predicted_malicious = response.text.split("Final Answer:")[-1].strip()
        # 执行相似性搜索
        results_with_scores = vectorstore.similarity_search_with_score(predicted_malicious, 6)
        results = [result[0] for result in results_with_scores]
        scores = [result[1] for result in results_with_scores]
        related_attack_info = []
        for result in results:
            attack_category = result.metadata.get('attack_category', 'Unknown Category')
            page_content = result.page_content
            if len(page_content) > 1000:
                page_content = page_content[:1000]  # Keep only the first 1000 characters
            
            related_attack_info.append(f"Related attack vector: {page_content}, Attack Category: {attack_category}")

        retrive_attack_vector = "\n".join(related_attack_info)
        
        # 构建新的输入
        taskid = data.id
        i = int(taskid) - 1
        assert data.label == test_dataset[i].label, f"Mismatch in labels for task ID {taskid}"
        input_text = json.dumps(
            {"method": test_dataset[i].method, "url": test_dataset[i].url, "body": test_dataset[i].body})
        final_input = prompt_analyse.format(input_text=input_text, malicious_part=predicted_malicious, retrive_attack_information=retrive_attack_vector)
        # 存储元数据以备后用
        metadata = {
            "predict_malicious_actthought": response.text,
            "predicted_malicious": predicted_malicious,
            "attack_vector": related_attack_info,
            "similarity_scores": scores,
            "final_input": final_input
        }
        data.metadata = metadata

    return task

### 阶段二：批量处理生成的输入
def process_inputs(pipe, task):

    final_inputs = []
    for data in task:
        final_str = data.metadata["final_input"]

        # 以 "# Input request" 作为分割点，分割 system 和 user
        idx = final_str.find("# Input request")
        if idx != -1:
            system_content = final_str[:idx]
            user_content = final_str[idx:]
        else:
            print("error")

        # 拼成 Chat 格式
        message = [
            {"role": "system", "content": system_content.strip()},
            {"role": "user", "content": user_content.strip()}
        ]
        final_inputs.append(message)
    
    print(final_inputs[0])

    for data, input in tqdm(zip(task, final_inputs), total=len(task)):
        if data.metadata["predicted_malicious"] == "":
            data.completed({"assistant": "normal"}, None)
        else:
            responses = pipe([input], gen_config=gen_config)  # 批量处理
            predicted = responses[0].text
            data.completed({"assistant": predicted}, None)

    return task

def process_with_local_imdeploy_model(model):
    # 判断 model 是否是特定的模型
    if model == 'LLM-Research/Meta-Llama-3.1-8B-Instruct':
        # 如果是这个模型，则带着 chat_template_config 初始化
        pipe = pipeline(model, backend_config=backend_config, chat_template_config=ChatTemplateConfig('llama3_1'))
    elif model == 'LLM-Research/Llama-3.2-3B-Instruct':
        pipe = pipeline(model, backend_config=backend_config, chat_template_config=ChatTemplateConfig('llama3_2'))
    elif 'Llama_3-8b' in model:
        pipe = pipeline(model, backend_config=backend_config, chat_template_config=ChatTemplateConfig('llama3'))
    else:
        # 如果不是这个模型，则按默认方式初始化
        pipe = pipeline(model, backend_config=backend_config)

    # task = generate_inputs(pipe)

    # # 将生成的任务在 "one-shot" 目录下保存为 task.jsonl
    # task.dump_task(args.result_dir, "task.jsonl")

    task_file_path = os.path.join(args.result_dir, "task.jsonl")
    if not os.path.exists(task_file_path):
        task = generate_inputs(pipe)
        task.dump_task(args.result_dir, "task.jsonl")
    else:
        task=LLM_task([])
        task.load_task(args.result_dir, "task.jsonl")

    # 阶段二：批量处理输入
    return process_inputs(pipe, task)


# 在代码的开始记录初始时间
start_time = time.time()

with open("LLM/Prompt/pdata.json", 'r', encoding='utf-8') as file:
    id_to_label = json.load(file)

current_time = datetime.now()
formatted_time = current_time.strftime("%Y-%m-%d-%H-%M-%S")
file_name = f"{formatted_time}_completed.jsonl"

task = process_with_local_imdeploy_model(args.model)

# 检查结果目录是否存在，如果不存在则创建
if not os.path.exists(args.result_dir):
    os.makedirs(args.result_dir)

task.dump_task(args.result_dir, file_name)

 # 在代码的末尾记录结束时间
end_time = time.time()
# 计算总运行时间
total_time = end_time - start_time
# 输出总运行时间
print(f"Total runtime of the script: {total_time} seconds")

data_analysis.llm_analysis_with_confusion_matrices(task.get_labels(), id_to_label, task.get_result(),args.result_dir)