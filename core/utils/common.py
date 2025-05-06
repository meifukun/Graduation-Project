import os
import pandas as pd
import glob
import collections
import torch


def parser_request(header, body='nan'):
    http_method, url = header.split()[0], header.split()[1]
    if str(body) == 'nan':
        body = ''
    return http_method, url, body


def get_data_from_file(path, func):
    rtn = []
    with open(path) as fd:
        for line in fd:
            line = line.strip()
            # if not line:
            #     continue
            rtn.append(func(line))
    return rtn


def load_db_from_dir(path_dir, content_type=None, max_size=None):
    if os.path.exists('/data_cfs/web_data/{}/'.format(path_dir)):
        base_path = 'data_cfs/web_data'
    else:
        raise Exception("Data <{}> not found!".format(path_dir))
    index = 0
    results = [[], [], []]  # http method, content, rid
    print('=========loading data: /{}/{}/============'.format(base_path, path_dir))
    all_files = len(glob.glob('/{}/{}/*.pk'.format(base_path, path_dir)))
    while True:
        print("\r loading... [{}/{}]".format(index,
              all_files), end='', flush=True)
        file_path = '/{}/{}/{}.pk'.format(base_path, path_dir, index)
        if not os.path.exists(file_path):
            break
        if max_size is not None:
            if index > max_size:
                break
        df_tmp = pd.read_pickle(file_path)
        urls = df_tmp['header'].to_list()
        bodys = df_tmp['body'].to_list()
        rid = df_tmp['id'].to_list()
        for req in zip(urls, bodys, rid):
            http_method, url, body = parser_request(req[0], req[1])
            # bypass the TST(Tencent Security Team)
            if "Tencent-Leakscan: TST(Tencent Security Team)" in req[0]:
                print(url)
                raise Exception("TST scan.")
            if content_type == 'url':
                body = ''
            if content_type == 'body':
                url = ''
            content = url + ' ' + body
            content = content.strip()
            results[0].append(http_method)
            results[1].append(content)
            results[2].append(req[2])
        index += 1
    print('\n', end='')
    return results


def merge_dict(dict_list: list, merge_type: str='sum') -> dict:
    """
    Merge multiple dict when using multiprocessing

    Parameters
    ----------
    dict_list : list
        The list of dicts to be merged

    merge_type : str
        'sum', 'list'
    Returns
    -------
    res : dict
        Merged dict
    """
    if merge_type == 'sum':
        res = {}
        for ob in dict_list:
            for k, v in ob.items():
                res[k] = res.get(k, 0) + v
    elif merge_type == 'list':
        res = collections.defaultdict(list)
        for ob in dict_list:
            for k, v in ob.items():
                res[k].extend(v)
    else:
        raise Exception("Unknow merge type.")
    return res


def worker_partition(all_tasks: list, num_worker: int) -> list:
    """
    Partition tasks for multiprocess

    Parameters
    ----------
    all_task : list
        The list of all task
    num_worker : int
        The number of workers
    Returns
    -------
    res : list
        Partitioned tasks, [[worker1 tasks], [worker2 tasks], ...]
    """
    total = len(all_tasks)
    res = []
    per, rem = divmod(total, num_worker)
    for i in range(0, rem):
        res.append([all_tasks[j] for j in range(i*(per+1), (i+1)*(per+1))])
    for i in range(rem, min(num_worker,total)):
        res.append([all_tasks[j] for j in range(i*per+rem, (i+1)*per+rem)])
    return(res)


def merge_voca(in_path_list, out_path):
    """
    Merge the vocabulary

    Parameters
    ----------
    in_path_list : list
        The list of in_path (e.g., xxx/voca.in)
    out_path : str
        out_path
    """
    all_voca = []
    for in_path in in_path_list:
        voca = get_data_from_file(in_path, str)
        all_voca.extend(voca)
    all_voca = list(set(all_voca))
    with open(f'{out_path}', 'w') as fd:
        for item in all_voca:
            fd.write('%s\n' % item)


def merge_U(in_path_list, out_path):
    """
    Merge the matrix U of universal

    Parameters
    ----------
    in_path_list : list
        The list of in_path (e.g., xxx/train.w2v)
    out_path : str
        out_path
    """
    def get_id2word(word2id):
        res = {}
        for k, v in word2id.items():
            res[v] = k
        id2word = []
        for i in range(len(res)):
            id2word.append(res[i])
        return id2word
    temp = torch.load(in_path_list[0])
    merged_vectors = temp['vectors']
    merged_word2id = temp['word2id']
    now = len(merged_word2id)
    for in_path in in_path_list[1:]:
        temp = torch.load(in_path)
        vectors = temp['vectors']
        word2id = temp['word2id']
        id2word = get_id2word(word2id)
        for index, w in enumerate(id2word, 0):
            if w not in merged_word2id:
                merged_word2id[w] = now
                now += 1
                merged_vectors = torch.cat([merged_vectors, vectors[index:index+1, :]], dim=0)
    res = {'vectors': merged_vectors, 'word2id': merged_word2id}
    torch.save(res, out_path)


def generate_voca(tmp_dir, file_name, out_name):
    token_seq = get_data_from_file(
            '{}/{}.in'.format(tmp_dir, file_name), str)
    token_set = set()
    for ts in token_seq:
        for token in ts.split():
            token_set.add(token)
    token_set = sorted(token_set)  # 按照字典序输出，确保每次输出的顺序一致
    with open('{}/{}.in'.format(tmp_dir, out_name), 'w') as fd:
        for token in token_set:
            fd.write('%s\n' % token)


if __name__ == '__main__':
    # test merge_type sum
    dict1 = {'a': 1, 'b': 10}
    dict2 = {'c': 1, 'a': 5, 'b': 20}
    res = merge_dict([dict1, dict2], merge_type='sum')
    print(res)
    # test merge_type list
    dict1 = {'a': ['a', 'b'], 'b': [10]}
    dict2 = {'c': [1], 'a': ['bb'], 'b': ['z']}
    res = merge_dict([dict1, dict2], merge_type='list')
    print(res)
    # test worker_partition
    a = list(range(289))
    res = worker_partition(a, 10)
    print(res)
