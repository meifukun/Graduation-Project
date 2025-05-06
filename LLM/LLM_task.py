from openai import OpenAI
import json
import os
import sys
from tqdm import tqdm
import time
import tiktoken
sys.path.append('.')
from core.inputter import HTTPDataset, RequestInfo


def num_tokens_from_string(string, encoding_name="cl100k_base"):
    """Returns the number of tokens in a text string."""
    encoding = tiktoken.get_encoding(encoding_name)
    num_tokens = len(encoding.encode(string))
    return num_tokens


class Message:
    def __init__(self, id, engin, model, request, metadata):
        self.id = id
        self.engin = engin
        self.request = request
        self.model = model
        self.metadata = metadata
        self.state = 'ready'

    def dump_label(self,label):
        self.label=label
    def get_label(self):
        return self.label

    def completed(self, response, setting):
        self.response = response
        self.setting = setting
        self.state = 'completed'
        self.dump_Messages()

    def dump_Messages(self):
        parameters = {}
        parameters["id"] = self.id
        parameters["engin"] = self.engin
        parameters["model"] = self.model
        parameters["request"] = self.request
        parameters["metadata"] = self.metadata
        parameters["state"] = self.state
        parameters["label"] = self.label
        if self.state == 'completed':
            parameters["response"] = self.response
            parameters["setting"] = self.setting
        return parameters
    def load_Messages(self, parameters):
        self.id = parameters.get("id")
        self.engin = parameters.get("engin")
        self.model = parameters.get("model")
        self.request = parameters.get("request")
        self.metadata = parameters.get("metadata")
        self.state = parameters.get("state")
        self.label = parameters.get("label")
        if self.state == 'completed':
            self.response = parameters.get("response")
            self.setting = parameters.get("setting")
    def get_num_tokens(self):
        if isinstance(self.request, str):
            return num_tokens_from_string(self.request)
        elif isinstance(self.request, dict) and "system" in self.request and "user" in self.request:
            temp_str = self.request["system"] + self.request["user"]
            return num_tokens_from_string(temp_str)
        else:
            request_content = {item[0]: item[1] for item in self.request}
            system_content = request_content.get("system", "")
            user_content = request_content.get("human", "")
            temp_str = system_content + user_content
            return num_tokens_from_string(temp_str)
    def get_result(self):
        return self.response["assistant"]
    def get_input(self):
        if isinstance(self.request, str):
            return self.request
        elif isinstance(self.request, dict) and "system" in self.request and "user" in self.request:
            temp_str = self.request["system"] + self.request["user"]
            return temp_str
        else:
            request_content = {item[0]: item[1] for item in self.request}
            system_content = request_content.get("system", "")
            user_content = request_content.get("human", "")
            temp_str = system_content + user_content
            return temp_str


class LLM_task:
    def __init__(self, task):
        self.task = task

    def __getitem__(self, index):
        return self.task[index]

    def __len__(self):
        return len(self.task)

    def get_result(self):
        result = []
        for req in self.task:
            if req.state == 'completed':
                result.append(req.response["assistant"])
            else:
                result.append("error")
        return result

    def get_labels(self):
        labels=[]
        for m in self.task:
            labels.append(m.get_label())
        return labels
    def dump_task(self, tmp_dir,file_name):
        task_file_path = os.path.join(tmp_dir, file_name)
        tasklist = []
        for req in self.task:
            tasklist.append(req.dump_Messages())

        with open(task_file_path, 'w', encoding='utf-8') as file:
            json.dump(tasklist, file, ensure_ascii=False, indent=4)
    
    def remove_task(self, message_obj):
        """
        从任务列表 self.task 中移除指定的 message_obj（Message 实例）。
        如果列表中不存在该 message_obj，会抛出 ValueError。
        """
        self.task.remove(message_obj)

    # def load_task(self, tmp_dir, file_name):
    #     task_file_path = os.path.join(tmp_dir, file_name)
    #     if os.path.exists(task_file_path):
    #         with open(task_file_path, 'r', encoding='utf-8') as file:
    #             tasklist = json.load(file)
    #             for task_params in tasklist:
    #                 req = Message(None, None, None, None, None)
    #                 req.load_Messages(task_params)
    #                 self.task.append(req)
    #     else:
    #         print(f"Task file not found: {task_file_path}")

    # def load_task(self, task_file_path):
    #     if os.path.exists(task_file_path):
    #         with open(task_file_path, 'r', encoding='utf-8') as file:
    #             tasklist = json.load(file)
    #             for task_params in tasklist:
    #                 req = Message(None, None, None, None, None)
    #                 req.load_Messages(task_params)
    #                 self.task.append(req)
    #     else:
    #         print(f"Task file not found: {task_file_path}")
    def load_task(self, *args):
        if len(args) == 1 and isinstance(args[0], str):  # 传入完整的路径
            task_file_path = args[0]
        elif len(args) == 2:  # 传入目录和文件名
            tmp_dir, file_name = args
            task_file_path = os.path.join(tmp_dir, file_name)
        else:
            print("Invalid arguments")
            return
        
        if os.path.exists(task_file_path):
            with open(task_file_path, 'r', encoding='utf-8') as file:
                tasklist = json.load(file)
                for task_params in tasklist:
                    req = Message(None, None, None, None, None)
                    req.load_Messages(task_params)
                    self.task.append(req)
        else:
            print(f"Task file not found: {task_file_path}")


    
    def count_tokens(self):
        num_tokens = 0
        for req in self.task:
            num_tokens += req.get_num_tokens()
        return num_tokens

    def print_token_length_distribution(self):
        """
        打印任务的 token 长度分布。
        """
        token_lengths = [req.get_num_tokens() for req in self.task]

        # 定义分布区间
        bins = [0, 4000, 8600, 10000, 12000, float('inf')]
        bin_labels = [
            "0-4000", "4001-8600", "8601-10000", "10001-12000", "12001+"
        ]
        bin_counts = {label: 0 for label in bin_labels}

        # 统计分布
        for length in token_lengths:
            for i in range(len(bins) - 1):
                if bins[i] <= length < bins[i + 1]:
                    bin_counts[bin_labels[i]] += 1
                    break

        # 打印统计信息
        print("Token Length Distribution:")
        for label, count in bin_counts.items():
            print(f"{label}: {count} tasks")

        # 打印统计数据
        print(f"\nTotal tasks: {len(token_lengths)}")
        print(f"Min token length: {min(token_lengths)}")
        print(f"Max token length: {max(token_lengths)}")
        print(f"Average token length: {sum(token_lengths) / len(token_lengths):.2f}")