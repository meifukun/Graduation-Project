import re
from urllib.parse import unquote_plus, urlparse, parse_qsl
from core.inputter import RequestInfo

def formatting(data, config, name=None):
    # 标点为单位分割
    def sub_punc(matched):
        return ' {} '.format(matched.group(0))
    # ????? 好像不需要 data = unquote_plus(data)
    data = re.sub(r'''(http:|https:|ftp:|www.|//)[^\{\}\(\)<>'"\+]+''', "__http__", data)  # 不匹配?=<>[]{}等
    # 需要再http之后，标点之前考虑影响
    # 切分字符包括&/[]{},.等除了下划线和反斜杠外的所有字符
    data = re.sub(r'[^a-zA-Z0-9_\-\\<>\[\]\{\}=\?\!\(\)\*\|&\.\+]+', ' ', data)
    # 将可能出现攻击情况的控制字符单列
    data = re.sub(r'[<>\[\]\{\}=\?\!\(\)\*\|&\.\+]', sub_punc, data)
    data = re.sub(r'(\b_\b)|(\\x[0-9a-f][0-9a-f])', ' ', data)
    data = re.sub(r'\\', '', data)


    # print(data)
    # data = re.sub(r'\b[a-z]\b', '__onechr__', data)
    # # 处理十进制
    # data = re.sub(r'(\b[0-9_]+\b)', '__pnum__', data)
    for key, value in config.rechara.items():
        if isinstance(value, list):  # value: ['__type__', name]
            if isinstance(value[1], list):
                if name in value[1]:
                    data = re.sub(key, value[0], data)
            elif isinstance(value[1], str):
                if name == value[1]:
                    data = re.sub(key, value[0], data)
        else:  # value: '__type__'
            data = re.sub(key, value, data)

    for key, value in config.deduplicate.items():
        data = re.sub(key, value, data)

    return data.split()


def rechara_data(data, config, strict=False):
    data = data.lower() #转小写hqf

    # ---- for datasets except for sns
    data = urlparse(data)

    # ---- sns only
    # old_data = data # ----for sns
    # data = urlparse(data)
    # if data[4] == '': 
    #     data = unquote_plus(old_data)
    #     data = urlparse(data)
        
    path = data[2]
    result = []
    #url解码
    path = unquote_plus(path)
    result.extend(formatting(path, config))

    sub_result = _sub_rechara_data(data[4],config,strict)
    result.extend(sub_result)
    return result


def _sub_rechara_data(query_ori, config, strict=False):
    result = []
    query = parse_qsl(query_ori, strict_parsing=strict)
    known_key = set()
    for name, value in query:
        #寻找新出现的key
        if name in known_key:
            continue
        known_key.add(name)
        #解码
        name = unquote_plus(name)
        value = unquote_plus(value)
        # print("{}: {}".format(name, value))
        result.extend(formatting(name, config))
        value = re.sub(r'[\?]{4,}', '未知', value)
        # 不太理解这里__sentence__的替换原则，[^\x00-\x7f]在匹配非ascll字符， %u[\d\w]{4} 是在匹配 %u然后4个字符？
        # if re.search(r'[^\x00-\x7f]', value) or re.search(r'%u[\d\w]{4}', value):
        #     value = "__sentence__"
        # elif (not re.search(r'''[\{\}\(\)<>'"\+]''', value)) and len(value.split()) >= 3:
        #     value = "__sentence__"
        if re.search(r'^(http:|https:|ftp:|www.|//)', value):  # startwith url
            value = "__http__"
        elif name in config.query_wl:  # 豁免字段
            value = config.query_wl[name]
        if re.search('&',value) or re.search('=',value):
            sub_res = _sub_rechara_data(value, config, strict)
            #result.extend('__subst__')
            result.extend(sub_res)
            #result.extend('__subed__')
        else:
            result.extend(formatting(value, config, name))
    return result

def build_vocb(data, max_size=None):
    # data: list of list of words, e.g. [['i', 'love', 'you'], ['he', 'hate', 'me']]
    word2id = {'<PAD>': 0, '<UNK>': 1}
    id2word = {0: '<PAD>', 1: '<UNK>'}
    word_count = {}
    #无重复地统计词频，形成词典
    for line in data:
        for word in line:
            if word not in word_count:
                word_count[word] = 1
            else:
                word_count[word] += 1

    word_count = sorted(word_count.items(), key=lambda x: x[1], reverse=True)
    if max_size is not None:
        word_count = word_count[:max_size]
    # word - index
    for word, _ in word_count:
        word2id[word] = len(word2id)
        id2word[len(id2word)] = word
    return word2id, id2word

def convert_sent_to_id(data, word2id, max_len):
    # data: list of list of words, e.g. [['i', 'love', 'you'], ['he', 'hate', 'me']]
    # word2id: dict, e.g. {'<PAD>': 0, '<UNK>': 1, 'i': 2, 'love': 3, 'you': 4, 'he': 5, 'hate': 6, 'me': 7}
    # max_len: int, e.g. 5
    # return: list of list of ids, e.g. [[2, 3, 4, 0, 0], [5, 6, 7, 0, 0]]
    data_id = []
    for line in data:
        line_id = []
        for word in line:
            if word in word2id:
                line_id.append(word2id[word])
            else:
                line_id.append(word2id['<UNK>'])
        if len(line_id) < max_len:
            line_id += [word2id['<PAD>']] * (max_len - len(line_id))
        else:
            line_id = line_id[:max_len]
        data_id.append(line_id)
    return data_id


def get_prompt(req):
    prompt = f"Method: {req.method} URL: {req.url} Body: {req.body}"
    return prompt


def _textcnn_paper_simple_tokenizer(s: str):
    def sub_punc(matched):
        return ' {} '.format(matched.group(0))
    s = unquote_plus(s, encoding='utf-8', errors='replace')
    # 标点为单位分割
    s = re.sub('\,|\;|\+|/|=|&|\'|\:|\?', ' ', s)
    # 将可能出现攻击情况的控制字符单列
    # 如果不将控制字符单列，就不需要各模块分开解码
    # data = re.sub(r'[<>\[\]\{\}=\?\!\(\)\*\|&\.\+]', sub_punc, data)
    s = s.split()
    s_r = []
    for i in s:
        s_r.append(i)
    return s_r


def char_tokenizer(req: RequestInfo):
    '''final: char level tokenizer'''
    s = unquote_plus(get_prompt(req), encoding='utf-8', errors='replace')  
    return list(s)


def warpped_tokenizer(req: RequestInfo):
    '''final: token level tokenizer'''
    return _textcnn_paper_simple_tokenizer(get_prompt(req))

