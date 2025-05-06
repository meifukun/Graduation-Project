
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

backend_config = TurbomindEngineConfig(cache_max_entry_count=0.2, tp=1)
gen_config = GenerationConfig(top_p=1.0,
                              top_k=50,
                              temperature=0.8,
                              max_new_tokens=6000,
                              do_sample=True)

test_dataset, test_data_json, test_cls_ground_truth, _ = load_datasets(args.test_path, "cpu")


with open("LLM/Prompt/Prompt_attack_cls_v0.txt", 'r', encoding='utf-8') as file:
    prompt_analyse = file.read()

from langchain_community.embeddings import OpenAIEmbeddings
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_community.vectorstores import Chroma


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
        prompt="",  # 来自之前的prompt定义
        model_name=args.model,
        max_tokens=6000,  # 根据模型上下文长度调整
    )

    for data in task:

        # 构建新的输入
        taskid = data.id
        i = int(taskid) - 1
        assert data.label == test_dataset[i].label, f"Mismatch in labels for task ID {taskid}"
        input_text = json.dumps(
            {"method": test_dataset[i].method, "url": test_dataset[i].url, "body": test_dataset[i].body})
        final_input = prompt_analyse.format(input_text=input_text)
        # 存储元数据以备后用
        metadata = {
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