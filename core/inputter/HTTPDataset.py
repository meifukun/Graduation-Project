import json
import os
import random
from tqdm import tqdm
from collections import Counter


class RequestInfo:
    def __init__(self, method, url, body, headers=None, starttimestamp=None, **kwargs):
        self.method = method
        self.url = url
        self.body = body
        self.headers = headers  # 新增headers
        self.starttimestamp = starttimestamp  # 新增时间戳属性
        assert len(kwargs) < 25, "Too many arguments"
        self.__dict__.update(kwargs)

    def __str__(self):
        # return json.dumps(self.request)
        return self.url
    
    def dump_json(self):
        return json.dumps(self.__dict__)

    @staticmethod
    def from_teleg(json_str):
        # json_str: str (raw json from china telecom)
        obj = json.loads(json_str)
        url = obj['requestHeader'].split()[1]
        body = 0
        return RequestInfo(obj['method'], url, body,
                           HTTPversion=obj['protocolVersion'],
                           severity=obj['severity'],
                           requestStatus=obj['requestStatus'],
                           responseCode=obj['responseCode'],
                           id=obj['id'])
    @staticmethod
    def from_CSIC2010( json_str ):
        obj = json.loads(json_str)
        url = obj["url"]
        body = obj["body"]
        method = obj["method"]
        if str(body) != "" :
            url = url + "?" + body
        body = 0
        return RequestInfo(  method, url, body,id=obj['id'])

    def serialize(self) -> bytes:
        """
        将对象序列化为 JSON 字节流
        """
        # 将 __dict__ 转为 JSON 字符串，再编码为 bytes
        return json.dumps(self.__dict__).encode('utf-8')

    @classmethod
    def deserialize(cls, data: bytes) -> 'RequestInfo':
        """
        从 JSON 字节流反序列化为 RequestInfo 对象
        """
        # 解码 bytes -> JSON 字符串 -> 字典
        obj_dict = json.loads(data.decode('utf-8'))
        # 提取基础属性
        method = obj_dict.pop('method')
        url = obj_dict.pop('url')
        body = obj_dict.pop('body')
        headers = obj_dict.pop('headers', None)
        starttimestamp = obj_dict.pop('starttimestamp', None)
        # 剩余属性作为 kwargs
        return cls(method, url, body, headers=headers, starttimestamp=starttimestamp, **obj_dict)
    



class HTTPDataset:
    def __init__(self, name, dataset):
        self.dataset = dataset  # list of RequestInfo
        self.name = name
        
    # def report_stat(self):
    #     # statistics
    #     self.total = len(self.dataset)
    #     self.method_counter = Counter()
    #     self.severity_counter = Counter()
    #     self.status_counter = Counter()
    #     self.code_counter = Counter()
    #     self.noquery_counter = 0
    #     for data in tqdm(self.dataset):
    #         self.method_counter[data.method] += 1
    #         self.severity_counter[data.severity] += 1
    #         self.status_counter[data.requestStatus] += 1
    #         self.code_counter[data.responseCode] += 1
    #         if not '?' in data.url:
    #             self.noquery_counter += 1
    #     print("#### Statistics #### ")
    #     print(f"Dataset: {self.name}")
    #     print(f"Total: {self.total}")
    #     print(f"Method: {self.method_counter}")
    #     print(f"Severity: {self.severity_counter}")
    #     print(f"RequestStatus: {self.status_counter}")
    #     print(f"ResponseCode: {self.code_counter}")
    #     print(f"No query: {self.noquery_counter}")
    
    def dump_datset(self, file_path, tag_list=[]):
        assert len(tag_list) <= 10
        file_name = self.name
        for tag in tag_list:
            file_name += f"_<{tag}>"
        # 如果file_path是一个路径，那么拼凑成一个文件名
        if os.path.isdir(file_path):
            out_file_path = os.path.join(file_path, f"{file_name}.jsonl")
        else:
            out_file_path = file_path
        # else:
        #     raise ValueError("file_path should be a file or a directory")
        with open(out_file_path, 'w') as outfile:
            for data in tqdm(self.dataset):
                dictionary = data.__dict__
                json.dump(dictionary, outfile)
                outfile.write('\n')
    
    def shuffle_dataset(self, seed=None):
        if seed is not None:
            random.seed(seed)
        random.shuffle(self.dataset)

    @staticmethod
    def load_from(file_path):
        dataset_list = []
        with open(file_path) as f:
            for line in tqdm(f):
                dataset_list.append(RequestInfo(**json.loads(line)))
        return HTTPDataset(file_path.split('/')[-1].split('.')[0], dataset_list)
    
    def load_from_csic(file_path):
        dataset_list = []
        with open(file_path) as f:
            for line in tqdm(f):
                dataset_list.append(RequestInfo.from_CSIC2010(line.strip()))
        return HTTPDataset(file_path.split('/')[-1].split('.')[0], dataset_list)
    
    def __getitem__(self, index):
        return self.dataset[index]

    def __len__(self):
        return len(self.dataset)
    
    def report_label_stat(self):
        label_counter = {}
        for req in self.dataset:
            if req.label not in label_counter:
                label_counter[req.label] = 0
            label_counter[req.label] += 1
        print(f"\n#### <{self.name}> dataset Total numbers: {len(self.dataset)} ####")
        # sort key
        for label in sorted(label_counter.keys()):
            print(f"Label {label}: {label_counter[label]} samples")
