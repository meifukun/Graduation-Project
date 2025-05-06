import re
from urllib.parse import urlparse, unquote_plus
from core.inputter import RequestInfo
from .tokenize import _textcnn_paper_simple_tokenizer


def is_form_urlencoded(body):
    pattern = r'^[\w.%+]+=[\S]*'
    return bool(re.match(pattern, body))


def get_http_level_split(req: RequestInfo):
    parsed = urlparse(req.url)
    path_parts = parsed.path.split('/')
    # print(req.url)
    # print(parsed)
    # print(path_parts)

    # # 检查URL路径是否以'/'开始，据此决定是否为第一个部分添加'/'
    # if parsed.path.startswith('/'):
    #     url_list = ['/' + part for part in path_parts if part]
    # else:
    #     # 第一个部分不加'/'
    #     url_list = [path_parts[0]] + ['/' + part for part in path_parts[1:] if part]
    url_list = ['/' + part for part in path_parts if part]


    query_list = parsed.query.split('&')
    
    # 检查请求体是否为表单数据
    if is_form_urlencoded(req.body):
        body_list = req.body.split('&')
    else:
        # 不是表单数据，将整个body作为一个元素
        body_list = [req.body] if req.body else []
    
    # 清理空的查询字符串
    if len(query_list) == 1 and query_list[0] == '':
        query_list = []
    
    # group = ['Method:', req.method] + ['URL:'] + url_list + (['?'] + query_list if query_list else []) + ['Body:'] + body_list
    group = [req.method] + url_list + (query_list if query_list else []) + body_list
    group = [item for item in group if item.strip()]
    return group


def get_http_level_split_furl(req: RequestInfo):
    parsed = urlparse(req.url)

    # 直接使用整个路径作为一个元素
    url_part = parsed.path

    query_list = parsed.query.split('&')
    # 检查请求体是否为表单数据
    if is_form_urlencoded(req.body):
        body_list = req.body.split('&')
    else:
        # 不是表单数据，将整个body作为一个元素
        body_list = [req.body] if req.body else []

    # 清理空的查询字符串
    if len(query_list) == 1 and query_list[0] == '':
        query_list = []

    # group = ['Method:'+ req.method] + ['URL:', url_part] + (['?'] + query_list if query_list else []) + ['Body:'] + body_list
    group = [req.method] + [url_part] + (query_list if query_list else []) + body_list
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


def char_tokenizer_with_http_level_alignment_furl(req: RequestInfo):
    all_list = []
    alignment = []
    group = get_http_level_split_furl(req)

    for p in group:
        p_list = list(unquote_plus(p, encoding='utf-8', errors='replace'))
        all_list.extend(p_list)
        
        decoded_p = unquote_plus(p, encoding='utf-8', errors='replace')  # 先对p进行解码
        # alignment.append([p, p_list])
        alignment.append([decoded_p, p_list])

    return all_list, alignment

def get_http_level_split_furl_header(req: RequestInfo):
    parsed = urlparse(req.url)

    # 直接使用整个路径作为一个元素
    url_part = parsed.path

    query_list = parsed.query.split('&')
    # 检查请求体是否为表单数据
    if is_form_urlencoded(req.body):
        body_list = req.body.split('&')
    else:
        # 不是表单数据，将整个body作为一个元素
        body_list = [req.body] if req.body else []

    # 清理空的查询字符串
    if len(query_list) == 1 and query_list[0] == '':
        query_list = []

    # 解析headers，以换行符分割成列表
    headers_list = req.headers.split('\n')

    # group = ['Method:'+ req.method] + ['URL:', url_part] + (['?'] + query_list if query_list else []) + ['Body:'] + body_list
    group = [req.method] + [url_part] + (query_list if query_list else []) + body_list + headers_list
    group = [item for item in group if item.strip()]
    return group

def char_tokenizer_with_http_level_alignment_furl_header(req: RequestInfo):
    
    all_list = []
    alignment = []
    group = get_http_level_split_furl_header(req)

    for p in group:
        p_list = list(unquote_plus(p, encoding='utf-8', errors='replace'))
        all_list.extend(p_list)
        
        decoded_p = unquote_plus(p, encoding='utf-8', errors='replace')  # 先对p进行解码
        # alignment.append([p, p_list])
        alignment.append([decoded_p, p_list])

    return all_list, alignment


def word_tokenizer_with_http_level_alignment(req: RequestInfo):
    all_list = []
    alignment = []
    group = get_http_level_split(req)

    for p in group:
        p_list = _textcnn_paper_simple_tokenizer(p)
        
        all_list.extend(p_list)
    
        decoded_p = unquote_plus(p, encoding='utf-8', errors='replace')  # 先对p进行解码
        # alignment.append([p, p_list])
        alignment.append([decoded_p, p_list])

    return all_list, alignment


def word_tokenizer_with_http_level_alignment_furl(req: RequestInfo):
    all_list = []
    alignment = []
    group = get_http_level_split_furl(req)

    for p in group:
        p_list = _textcnn_paper_simple_tokenizer(p)
        
        all_list.extend(p_list)
        
        decoded_p = unquote_plus(p, encoding='utf-8', errors='replace')  # 先对p进行解码
        # alignment.append([p, p_list])
        alignment.append([decoded_p, p_list])

    return all_list, alignment

def word_tokenizer_with_http_level_alignment_furl_header(req: RequestInfo):
    all_list = []
    alignment = []
    group = get_http_level_split_furl_header(req)

    for p in group:
        p_list = _textcnn_paper_simple_tokenizer(p)
        
        all_list.extend(p_list)
        
        decoded_p = unquote_plus(p, encoding='utf-8', errors='replace')  # 先对p进行解码
        # alignment.append([p, p_list])
        alignment.append([decoded_p, p_list])

    return all_list, alignment

