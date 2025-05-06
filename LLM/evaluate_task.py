
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

parser.add_argument("--result_dir", type=str, required=True, help="the path of result dir")
parser.add_argument('--file_name',type=str)
parser.add_argument('--test_path', default="hmm/malicious_requests.jsonl",type=str)

args = parser.parse_args()

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

test_dataset, test_data_json, test_cls_ground_truth, _ = load_datasets(args.test_path, "cpu")

with open("LLM/Prompt/pdata.json", 'r', encoding='utf-8') as file:
    id_to_label = json.load(file)

task=LLM_task([])
task.load_task(args.result_dir,args.file_name)

data_analysis.llm_analysis_single(task,test_dataset,task.get_labels(), id_to_label, task.get_result(),args.result_dir)

# python LLM/evaluate_task.py --result_dir result/qwen-iid --file_name 2025-03-26-20-08-56_completed.jsonl --test_path hmm/malicious_requests.jsonl