import json
import os
import math
import time
from urllib.parse import urlparse, parse_qs, unquote
from joblib import load
import numpy as np

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

def detect_anomalies(test_file, models, result_file, attack_file):
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
    
    with open(test_file) as fin, \
         open(result_file, 'w') as fout, \
         open(attack_file, 'w') as fattack:  # 新增攻击记录文件
        for line in fin:
            req = json.loads(line)
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
                fattack.write(line)
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
                fattack.write(line)
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
    #     test_file="tmp_dir/pdata/test_waf.jsonl",
    #     models=models,
    #     result_file="hmm/detection_results1.jsonl",
    #     attack_file="hmm/malicious_requests1.jsonl"
    # )
    # 记录开始时间
    start_time = time.time()
    detect_anomalies(
        test_file="tmp_dir/pdata-ood/test_waf.jsonl",
        models=models,
        result_file="hmm/detection_results-ood1.jsonl",
        attack_file="hmm/malicious_requests-ood1.jsonl"
    )
    # 记录结束时间
    end_time = time.time()
    
    # 计算并打印运行时间
    elapsed_time = end_time - start_time
    print(f"Detect anomalies execution time: {elapsed_time:.2f} seconds")