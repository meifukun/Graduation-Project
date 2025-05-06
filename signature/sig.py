import editdistance
import re,sys
import numpy as np
sys.path.append('.')
from LLM.LLM_task import LLM_task, Message

def initialize_distance_matrix(strings):
    n = len(strings)
    distance_matrix = np.full((n, n), float('inf'))  # 初始化距离为无穷大
    for i in range(n):
        for j in range(i + 1, n):
            len_i, len_j = len(strings[i]), len(strings[j])
            if 0.667 <= len_i / len_j <= 1.5:  # 检查长度比条件
                distance = editdistance.eval(strings[i], strings[j])
                if distance < (len_i + len_j) / 4:  # 检查距离条件；用过3，特别不好，用了4还可以，用5更加严格质量更高
                    distance_matrix[i, j] = distance
                    distance_matrix[j, i] = distance
    return distance_matrix

def update_representative(cluster_ids, active, distance_matrix):
    n = len(cluster_ids)
    unique_clusters = np.unique(cluster_ids[active])
    for cluster in unique_clusters:
        # 找到属于这个聚类的所有成员
        members = np.where(cluster_ids == cluster)[0]
        if len(members) == 1:
            continue  # 只有一个成员，无需更新
        min_distance_sum = float('inf')
        best_representative = members[0]
        # 遍历每个成员，计算与聚类中其他成员的总距离
        for member in members:
            distance_sum = np.sum(distance_matrix[member, members])
            if distance_sum < min_distance_sum:
                min_distance_sum = distance_sum
                best_representative = member
        # 更新代表
        active[members] = False
        active[best_representative] = True

def cluster_tokens(strings, part_types):
    n = len(strings)
    cluster_ids = np.arange(n)  # 初始时每个字符串自成一组
    print(n)
    distance_matrix = initialize_distance_matrix(strings)
    print(distance_matrix)
    active = np.ones(n, dtype=bool)  # 活动的代表标志

    while np.sum(active) > 1:
        min_distance = float('inf')
        x, y = -1, -1

        for i in range(n):
            if not active[i]:
                continue
            for j in range(i + 1, n):
                if active[j] and distance_matrix[i][j] < min_distance:
                    min_distance = distance_matrix[i][j]
                    x, y = i, j

        if min_distance == float('inf'):
            break

        # 合并聚类，更新聚类ID，使用较小的ID作为新聚类的ID
        new_id = min(cluster_ids[x], cluster_ids[y])
        old_id = max(cluster_ids[x], cluster_ids[y])

        # 打印合并信息以及对应的字符串内容
        print(f"合并聚类: {x} 和 {y}，新的聚类ID: {new_id}")
        print(f"字符串1: {strings[x]}")
        print(f"字符串2: {strings[y]}")

        # 更新所有原来属于old_id的元素，现在改为new_id
        cluster_ids[cluster_ids == old_id] = new_id
        active[y] = False  # 禁用y聚类的活跃状态

        # 更新聚类代表
        update_representative(cluster_ids, active, distance_matrix)

    # 根据 cluster_ids 同步类型信息
    final_clusters = {cid: [] for cid in set(cluster_ids)}
    type_clusters = {cid: [] for cid in set(cluster_ids)}
    for idx, cid in enumerate(cluster_ids):
        final_clusters[cid].append(strings[idx])
        type_clusters[cid].append(part_types[idx])

    # 聚集同一聚类的类型信息
    final_type_clusters = [list(set(types)) for types in type_clusters.values()]

    return list(final_clusters.values()), final_type_clusters


def longest_common_subsequence(s1, s2):
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

    lcs = []
    i, j = m, n
    while i > 0 and j > 0:
        if s1[i - 1] == s2[j - 1]:
            lcs.append(s1[i - 1])
            i -= 1
            j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            i -= 1
        else:
            j -= 1

    lcs.reverse()

    # Insert spaces where characters are not adjacent in original strings
    spaced_lcs = []
    last_i, last_j = -1, -1  # Initialize to invalid indexes
    for char in lcs:
        current_i = s1.find(char, last_i + 1)
        current_j = s2.find(char, last_j + 1)
        if last_i != -1 and (current_i != last_i + 1 or current_j != last_j + 1):
            spaced_lcs.append(' ')
        spaced_lcs.append(char)
        last_i, last_j = current_i, current_j

    return ''.join(spaced_lcs)

print(longest_common_subsequence("abcmnxyz","abopcxyz"))

def find_common_subsequence(str_list):
    if not str_list:
        return ""
    if len(str_list) == 1:
        return str_list[0]

    # 将列表中的所有字符串转换为小写
    str_list = [s.lower() for s in str_list]

    # 先找出前两个字符串的最长公共子序列
    common_sub = longest_common_subsequence(str_list[0], str_list[1])

    # 逐个与后续字符串比较，不断缩小公共子串范围
    for s in str_list[2:]:
        common_sub = longest_common_subsequence(common_sub, s)
        if not common_sub:  # 如果公共子串长度缩减至0，提前结束
            break

    return common_sub

def decode_and_update_regex(expression):
    # 查找所有%后跟两个十六进制数字的模式
    encoded_parts = re.findall(r'%[0-9a-fA-F]{2}', expression)
    new_expression = expression

    for part in encoded_parts:
        new_expression = new_expression.replace(part, r'.*')

    return new_expression

def remove_outlier_based_on_distance(cluster):
    if len(cluster) <= 5:
        return cluster

    # 计算聚类内所有元素之间的编辑距离
    n = len(cluster)
    distance_matrix = np.zeros((n, n))
    for i in range(n):
        for j in range(i + 1, n):
            distance_matrix[i, j] = distance_matrix[j, i] = editdistance.eval(cluster[i], cluster[j])

    # 计算每个元素到其他所有元素的距离总和
    distance_sums = np.sum(distance_matrix, axis=1)

    # 找到距离总和最大的元素索引
    max_distance_index = np.argmax(distance_sums)

    # 删除距离总和最大的元素
    return [cluster[i] for i in range(n) if i != max_distance_index]

def generate_signatures(clusters, type_clusters):
    """
    从每个聚类的公共子序列生成正则表达式签名。
    :param clusters: 字符串聚类列表。
    :return: 正则表达式签名列表。
    """
    signatures = []
    valid_types = []
    valid_clusters = []
    for idx, cluster in enumerate(clusters):
        # cluster = remove_outlier_based_on_distance(cluster)

        common_subseq = find_common_subsequence(cluster)
        # 移除结尾的反斜杠，如果存在
        common_subseq = common_subseq.rstrip('\\')
        common_subseq = clean_up_line(common_subseq)
        if common_subseq:
            # 先替换所有的空白字符为 '.*'，这样能匹配任何字符（包括空白和非空白字符）
            temp_signature = re.sub(r'[\s]+', r'.*', common_subseq)

            # 然后对生成的模式字符串进行转义，但需要保证我们插入的 '.*' 不被转义
            # 先转义整个字符串，然后替换转义后的 '\.\*' 为 '.*'
            signature = re.escape(temp_signature).replace(r'\.\*', r'.*')
        else:
            # 如果没有有效的公共子序列，使用空字符串作为签名
            signature = ''

        # 检查signature是否有效，且不只包含特殊模式
        if signature and signature not in ['/', '.*']:
            valid_types.append(type_clusters[idx])  # 只保存生成了签名的聚类的类型信息
            signatures.append(decode_and_update_regex(signature))
            valid_clusters.append(cluster)  # 添加有效的聚类到列表中

    return signatures, valid_types, valid_clusters

def main(attack_strings, part_types, detailed_name, results_name1,results_name2, min_length):
    """
    主函数，整合了聚类、找公共子序列和生成签名的步骤。
    :param attack_strings: 攻击字符串列表。
    :param distance_threshold: 聚类的编辑距离阈值。
    """
    clusters, type_clusters = cluster_tokens(attack_strings,part_types)
    print("Length of clusters:", len(clusters))
    print("Length of type_clusters:", len(type_clusters))
    signatures, valid_types, clusters = generate_signatures(clusters,type_clusters)
    print("Length of signatures:", len(signatures))
    print("Length of valid_types:", len(valid_types))
    # 新增：统计聚类信息
    cluster_sizes = [len(cluster) for cluster in clusters]
    print_cluster_statistics(cluster_sizes)

    # 新增：保存聚类详细信息和签名
    save_cluster_details(clusters, signatures, valid_types, detailed_name, results_name1, results_name2, min_length=min_length)

    return signatures


def save_cluster_details(clusters, signatures, valid_types, filename, special_filename, normal_filename, min_size=10, min_length=10):
    # 打印各列表长度以确保对齐
    print("Length of clusters:", len(clusters))
    print("Length of signatures:", len(signatures))
    print("Length of valid_types:", len(valid_types))
    """
    按聚类大小排序并保存每个聚类的详细信息和生成的签名。
    特殊文件按类别保存不符合一定条件的签名，正常文件保存完全符合条件的签名。
    :param clusters: 聚类列表，每个聚类包含多个字符串。
    :param signatures: 为每个聚类生成的正则表达式签名列表。
    :param valid_types: 与每个签名对应的类型列表。
    :param filename: 保存聚类详细信息的文件名。
    :param special_filename: 保存特殊情况签名的文件名。
    :param normal_filename: 保存正常情况签名的文件名。
    :param min_size: 定义正常聚类的最小成员数量。
    :param min_length: 定义正常签名的最小长度。
    """
    # 分类收集特殊签名
    short_signatures = []
    small_cluster_signatures = []
    substring_signatures = []

    # 绑定聚类、签名和类型，然后按聚类大小排序
    cluster_details = sorted(zip(clusters, signatures, valid_types), key=lambda x: len(x[0]))

    with open(filename, 'w') as file, open(special_filename, 'w') as special_file, open(normal_filename, 'w') as normal_file:
        for cluster, signature, types in cluster_details:
            # 写入聚类大小和类型
            file.write(f"Cluster size: {len(cluster)} - Types: {', '.join(types)}\n")
            for item in cluster:
                file.write(f"{item}\n")
            file.write(f"Generated Signature: {signature}\n\n" + "-"*50 + "\n")

            # 计算去掉所有 '.*' 后的签名长度
            signature_length = len(re.sub(r'\.\*', '', signature))

            # 根据不同条件分类处理签名
            if signature_length < min_length:
                short_signatures.append((signature, types))
                continue

            # if len(cluster) < min_size and signature_length < 15:
            #     small_cluster_signatures.append((signature, types))
            #     continue

            if any(sig != signature and signature in sig for sig in signatures):
                substring_signatures.append((signature, types))
                # continue

            # 保存正常签名
            normal_file.write(f"{signature}\n")
            normal_file.write(f"Types: {', '.join(types)}\n")

        # 保存特殊签名
        if short_signatures:
            special_file.write("过短的签名:\n")
            for sig, types in short_signatures:
                special_file.write(f"{sig}\n")
                special_file.write(f"Types: {', '.join(types)}\n")

        if small_cluster_signatures:
            special_file.write("小聚类签名:\n")
            for sig, types in small_cluster_signatures:
                special_file.write(f"{sig}\n")
                special_file.write(f"Types: {', '.join(types)}\n")

        if substring_signatures:
            special_file.write("子串签名:\n")
            for sig, types in substring_signatures:
                special_file.write(f"{sig}\n")
                special_file.write(f"Types: {', '.join(types)}\n")


def print_cluster_statistics(cluster_sizes):
    """
    打印聚类大小的统计信息。
    :param cluster_sizes: 每个聚类的大小列表。
    """
    from collections import Counter
    size_count = Counter(cluster_sizes)
    intervals = {}
    
    # 定义区间
    ranges = [(1, 1), (2, 2), (3, 5), (6, 10), (11, 20), (21, 50), (51, 100), (101, float('inf'))]
    
    # 初始化区间计数
    for r in ranges:
        intervals[r] = 0
    
    # 统计每个区间的聚类数
    for size in cluster_sizes:
        for r in ranges:
            if r[0] <= size <= r[1]:
                intervals[r] += 1
                break
    
    # 打印统计结果
    print("聚类大小区间统计：")
    for r in ranges:
        if r[1] == float('inf'):
            print(f"{r[0]}+ : {intervals[r]}")
        else:
            print(f"{r[0]}-{r[1]} : {intervals[r]}")

def extract_abnormal_http_parts(task_dir,file_name):
    task=LLM_task([])
    task.load_task(task_dir,file_name)

    abnormal_http_parts = []  # 用于存储所有异常HTTP部分的列表
    filtered_part_types = []

    for data in task:
        if data.metadata["predicted_malicious"] != "":
            abnormal_http_parts.append(data.metadata["predicted_malicious"])
            filtered_part_types.append("others")

    return abnormal_http_parts, filtered_part_types


def clean_up_line(line):
    # 清理输入行，去除非打印字符和多余的空白
    line = line.replace('"', ' ')
    # 使用正则表达式替换连续的空格为单个空格
    line = re.sub(r'\s+', ' ', line)
    return line.strip()


def process_data_and_generate_signatures(task_dir,input_file, detail_file, human_file, auto_file,min_length):
    # 读取原始数据
    abnormal_parts_list, part_types = extract_abnormal_http_parts(task_dir,input_file)
 
    # 执行主处理流程
    signatures = main(abnormal_parts_list, part_types , detail_file, human_file, auto_file, min_length)

    return signatures


import concurrent.futures
def execute_parallel_tasks():
    tasks = [
        # ('result/qwen-ood', "task.jsonl", "signature/qwen-ood/detail.txt", "signature/qwen-ood/human.txt", "signature/qwen-ood/auto.txt",5),
        ('result/qwen-iid', "task.jsonl", "signature/qwen-iid/detail.txt", "signature/qwen-iid/human.txt", "signature/qwen-iid/auto.txt",5)
    ]

    # 使用 ProcessPoolExecutor 来并行执行任务
    with concurrent.futures.ProcessPoolExecutor() as executor:
        futures = [executor.submit(process_data_and_generate_signatures, *task) for task in tasks]
        for future in concurrent.futures.as_completed(futures):
            print(future.result())  # 可以处理每个任务的结果，这里只是简单打印出来

# 假设现在要执行所有任务
execute_parallel_tasks()
