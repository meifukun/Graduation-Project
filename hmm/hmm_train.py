import json
import os
import math
from urllib.parse import urlparse, parse_qs, unquote
from hmmlearn import hmm
import numpy as np
from joblib import dump

# 超参数配置
HMM_CONFIG = {
    'n_components': 4,    # 隐状态数量
    'n_iter': 100,        # 最大迭代次数
    'prob_threshold': 0.1 # 异常概率阈值
}

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
        content_type = request.get('headers', {}).get('Content-Type', '')
        if 'application/json' in content_type:
            try:
                body_params = json.loads(request['body'])
                body_params = {k: [str(v)] for k, v in body_params.items()}
            except:
                pass
        else:
            body_params = parse_qs(request['body'])
    
    sorted_body = sorted(body_params.keys())
    
    # 构建标识符
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

def prepare_sequences(values):
    """准备HMM训练序列"""
    sequences = []
    for val in values:
        encoded = [ord(c) for c in encode_value(val)]
        sequences.append(np.array(encoded).reshape(-1, 1))
    return sequences

def train_models(train_file, model_dir):
    """主训练函数"""
    # 加载并分组训练数据
    requests_by_identifier = {}
    with open(train_file) as f:
        for line in f:
            req = json.loads(line)
            if req['label'] != 0:
                continue
            
            identifier = create_identifier(req)
            requests_by_identifier.setdefault(identifier, []).append(req)
    
    # 为每个identifier训练模型
    for identifier, requests in requests_by_identifier.items():
        # 提取所有参数名
        param_set = set()
        for req in requests:
            # 解析查询参数
            query_params = parse_qs(urlparse(req['url']).query)
            param_set.update(query_params.keys())
            
            # 解析body参数
            if req['body']:
                try:
                    body_params = parse_qs(req['body'])
                    param_set.update(body_params.keys())
                except:
                    pass
        
        # 为每个参数训练模型
        for param in param_set:
            # 收集该参数的所有值
            param_values = []
            for req in requests:
                # 从查询参数获取
                query_params = parse_qs(urlparse(req['url']).query)
                param_values.extend(query_params.get(param, []))
                
                # 从body参数获取
                if req['body']:
                    try:
                        body_params = parse_qs(req['body'])
                        param_values.extend(body_params.get(param, []))
                    except:
                        pass
            
            # 训练HMM模型
            if len(param_values) >= 5:  # 至少需要5个样本
                try:
                    sequences = prepare_sequences(param_values)
                    X = np.concatenate(sequences)
                    lengths = [len(s) for s in sequences]
                    
                    model = hmm.CategoricalHMM(
                        n_components=HMM_CONFIG['n_components'],
                        n_iter=HMM_CONFIG['n_iter']
                    )
                    model.fit(X, lengths=lengths)
                    
                    # 保存模型
                    safe_id = identifier.replace('|', '__').replace('/', '_')
                    model_path = os.path.join(
                        model_dir,
                        f"{safe_id}__{param}.joblib"
                    )
                    dump(model, model_path)
                except Exception as e:
                    print(f"训练失败: {identifier} - {param}: {str(e)}")

if __name__ == "__main__":
    train_models(
        train_file="tmp_dir/pdata/train.jsonl",
        model_dir="hmm_model"
    )