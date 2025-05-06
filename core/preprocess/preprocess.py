import re
import collections
import pickle
import pandas as pd
from tqdm import tqdm
from multiprocessing import Pool
from .tokenize import rechara_data
from core.utils import worker_partition, merge_dict

VALID_METHODS = {'GET', 'POST', 'HEAD'}
PREDEFINED_SYMBOLS = {'__other__', '__http__', '__pnum__', '__phex__', '__pbas__', '*'}

# 观察hex, bas和 rechara中正则表达式的关系，确定该在什么地方增加配置信息

def _sub_load_data(all_requests, content_type):
    '''
    all_requests: list of RequestInfo
    content_type: 'url', 'body', 'all'
    '''
    results = [[], [], []]  # http method, content, rid
    for request in all_requests:
        http_method, url, body = request.method, request.url, request.body
        if content_type == 'url':
            body = ''
        if content_type == 'body':
            url = ''
        content = url + ' ' + body
        content = content.strip()
        results[0].append(http_method)  # http_method
        results[1].append(content)  # content
        results[2].append(request.id)  # rid
    return results


def _sub_extract_tokens(all_requests, process_config, content_type):
    '''
    all_requests: list of RequestInfo    content_type:url
    '''
    words, cand_hex, cand_bas = {}, {}, {}
    valid_req_num = 0
    req_num_per_method = {}
    pattern_hex = re.compile(process_config.pattern_hex) #匹配16进制字符
    pattern_bas = re.compile(process_config.pattern_bas) #匹配数字加英文字符
    requests = _sub_load_data(all_requests, content_type) 
    http_method, contents = requests[0], requests[1]
    requests = list(zip(http_method, contents))
    for req in tqdm(requests):
        http_method, content = req[0], req[1]
        if http_method not in VALID_METHODS:
            continue
        try:
            #分词实现在了rechara_data
            ws = rechara_data(content, process_config, strict=False)
        except:
            continue
        req_num_per_method[http_method] = req_num_per_method.get(
            http_method, 0) + 1
        valid_req_num += 1
        for t in ws:
            # 将出现频次较多的十六进制或字符串写入词表
            if pattern_hex.match(t):
                cand_hex[t] = cand_hex.get(t, 0) + 1
            elif pattern_bas.match(t):
                cand_bas[t] = cand_bas.get(t, 0) + 1
            else:
                words[t] = words.get(t, 0) + 1
    return words, cand_hex, cand_bas, valid_req_num, req_num_per_method


def extract_tokens(all_requests, n_split, min_count, process_config, content_type, cand_min_count=10000):
    '''
    Return: words, cand_hex, cand_bas, tokens
    tokens: set of tokens
    words: frequency dict of all tokens
    '''
    print('=========building vocabulary============')
    with Pool() as pool:
        partition = worker_partition(all_requests, n_split)
        # print(partition)
        partition = [(p, process_config, content_type) for p in partition]
        # sub_extract就是在分词了
        res = pool.starmap(_sub_extract_tokens, partition)
        # print(type(res), len(res), len(res[0]), type(res[0]))
    # merge the results
    words = merge_dict([r[0] for r in res], 'sum')#这里放的是普通的key
    cand_hex = merge_dict([r[1] for r in res], 'sum')
    cand_bas = merge_dict([r[2] for r in res], 'sum')
    valid_req_num = sum([r[3] for r in res])
    req_num_per_method = merge_dict([r[4] for r in res], 'sum')
    # data writer
    tokens = []
    for k, v in words.items():
        if v >= min_count:
            tokens.append(k)
    #一些出现比较多的16进制表示
    for cand in [cand_hex, cand_bas]:
        for k, v in cand.items():
            if v >= cand_min_count:
                tokens.append(k)
    tokens = set(tokens)
    tokens = tokens | PREDEFINED_SYMBOLS
    print('total valid req num: %d' % valid_req_num)
    print('per method: %s' % str(req_num_per_method))
    print('tokens num: %d' % len(tokens))
    # sort for debug only
    cand_hex = sorted(cand_hex.items(), key=lambda x: x[1], reverse=True)
    cand_bas = sorted(cand_bas.items(), key=lambda x: x[1], reverse=True)
    words = sorted(words.items(), key=lambda x: x[1], reverse=True)
    # with open('{}/vocab_debug.in'.format(args.tmp_dir), 'w') as fd:
    #     for pair in words:
    #         fd.write('%s %d\n' % pair)
    # with open('{}/hex_debug.in'.format(args.tmp_dir), 'w') as fd:
    #     for pair in cand_hex:
    #         fd.write('%s %d\n' % pair)
    # with open('{}/bas_debug.in'.format(args.tmp_dir), 'w') as fd:
    #     for pair in cand_bas:
    #         fd.write('%s %d\n' % pair)
    return words, cand_hex, cand_bas, tokens


def extract_tokens_writer(tmp_dir, words, cand_hex, cand_bas, tokens):
    with open('{}/vocab.in'.format(tmp_dir), 'w') as fd:
        fd.write('<unk>\n<s>\n</s>\n')
        for item in tokens:
            fd.write('%s\n' % item)
    with open('{}/vocab_debug.in'.format(tmp_dir), 'w') as fd:
        for pair in words:
            fd.write('%s %d\n' % pair)
    with open('{}/hex_debug.in'.format(tmp_dir), 'w') as fd:
        for pair in cand_hex:
            fd.write('%s %d\n' % pair)
    with open('{}/bas_debug.in'.format(tmp_dir), 'w') as fd:
        for pair in cand_bas:
            fd.write('%s %d\n' % pair)


def _sub_handle_data(all_requests, tokens, process_config, content_type, repeat=False):
    # load tokends
    tokens = set(tokens)
    seq_cnt = collections.OrderedDict()  # 这里暂时没有用到ordered特性
    seq_rid_dict = collections.defaultdict(list)
    seq_content_dict = collections.defaultdict(list)
    pattern_hex = re.compile(process_config.pattern_hex)
    pattern_bas = re.compile(process_config.pattern_bas)
    error_export = []
    requests = _sub_load_data(all_requests, content_type)
    http_method, contents, rids = requests[0], requests[1], requests[2]
    requests = list(zip(http_method, contents, rids))
    for req in tqdm(requests):
        http_method, content, rid = req[0], req[1], req[2]
        if http_method not in VALID_METHODS:
            continue
        try:
            ws = rechara_data(content, process_config, strict=False)
        except:
            error_ws = rechara_data(content, process_config, strict=False)
            error_export.append([' '.join(error_ws), content])
            continue
        new_ws = []
        for t in ws:
            if pattern_hex.match(t) and t not in tokens:
                tok = '__phex__'
            elif pattern_bas.match(t) and t not in tokens:
                tok = '__pbas__'
            elif t in tokens:
                tok = t
            else:
                tok = '__other__'
            # Avoid duplicate tokens
            if not repeat and tok in PREDEFINED_SYMBOLS and len(new_ws) > 0 and new_ws[-1] == tok:
                continue
            new_ws.append(tok)
        if len(new_ws) == 0:
            continue
        tokenseq = ' '.join(new_ws)
        seq_cnt[tokenseq] = seq_cnt.get(tokenseq, 0) + 1
        # reverse dict for index-debug
        seq_rid_dict[tokenseq].append(rid)
        if len(seq_content_dict[tokenseq]) < 5:
            seq_content_dict[tokenseq].append(content)
    return seq_cnt, seq_rid_dict, seq_content_dict, error_export


# covert requests to token sequence
def handle_data(all_requests, n_split, tokens, process_config, content_type):
    # http_method, contents, rids = requests[0], requests[1], requests[2]
    # requests = list(zip(http_method, contents, rids))
    print('=========handle sequence: {}============')
    with Pool() as pool:
        partition = worker_partition(all_requests, n_split)
        partition = [(p, tokens, process_config, content_type) for p in partition]
        res = pool.starmap(_sub_handle_data, partition)
        # print(type(res), len(res), len(res[0]), type(res[0]))
    # merge the results
    # print("flag1")
    seq_cnt = merge_dict([r[0] for r in res], 'sum')
    # print("flag2")
    seq_rid_dict = merge_dict([r[1] for r in res], 'list')
    # print("flag3")
    seq_content_dict = merge_dict([r[2] for r in res], 'list')
    # print("flag4")
    error_export = []
    for r in res:
        error_export.extend(r[3])
    return seq_cnt, seq_rid_dict, seq_content_dict, error_export


def handle_data_writer(tmp_dir, path_dir, seq_cnt, seq_rid_dict, seq_content_dict, error_export):
    pickle.dump(seq_rid_dict, open('{}/{}.index.rid'.format(tmp_dir, path_dir), "wb" ))
    pickle.dump(seq_content_dict, open('{}/{}.index'.format(tmp_dir, path_dir), "wb" ))
    with open('{}/{}.in'.format(tmp_dir, path_dir), 'w') as fd_in:
        with open('{}/{}.y'.format(tmp_dir, path_dir), 'w') as fd_y:
            for seq, cnt in seq_cnt.items():
                fd_in.write('%s\n' % seq)
                fd_y.write('%d\n' % cnt)
    print("total error:{}".format(len(error_export)))
    df_error = pd.DataFrame(error_export, columns=['token seq', 'content'])
    df_error.to_excel('{}/{}_error_process.xlsx'.format(tmp_dir, path_dir))
    print('total <{}> requests:'.format(path_dir), sum(seq_cnt.values()))
    print('total <{}> sqenece::'.format(path_dir), len(seq_cnt))
