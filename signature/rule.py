import re

def clean_string(input_string):
    """
    清理字符串，移除不可见字符和控制字符。
    """
    if not input_string:
        return input_string

    # 移除不可见字符和控制字符（ASCII 0-31 和 127）
    cleaned_string = re.sub(r'[\x00-\x1F\x7F]', '', input_string)
    return cleaned_string

def is_valid_param_name(param):
    """
    检查参数名是否合法（不包含特殊字符）。
    """
    # 合法的参数名只允许字母、数字、下划线和点
    return re.match(r'^[a-zA-Z0-9_.-]+$', param) is not None

def generate_waf_rules_withloc(filename, output_filename):
    """
    从文件中读取包含正则表达式和具体类型（及参数名）的信息，生成针对这些参数的WAF规则。
    """
    try:
        with open(filename, 'r') as file, open(output_filename, 'w') as outfile:
            rule_id = 1000000  # 初始规则ID
            current_regex = None

            for line in file:
                line = line.strip()
                if line.startswith('Types:'):
                    # 去除"Types:"标识符并处理余下的部分
                    types_info = line[6:].strip()  # 移除'Types: '部分
                    types = types_info.split(', ')
                    use_generic = False  # 标记是否使用通用规则

                    target_fields = []

                    # 解析类型和参数
                    for type_info in types:
                        if ':' in type_info:  # 包含具体参数
                            type_part, param = type_info.split(':', 1)  # 按照第一个冒号分割
                            type_part = type_part.strip()
                            param = param.strip()

                            # 检查参数名是否包含特殊字符
                            if not is_valid_param_name(param):
                                use_generic = True  # 标记需要通用规则
                            if not use_generic:
                                if type_part == 'Query':
                                    target_fields.append(f"ARGS_GET:{param}")
                                    # target_fields.append(f"ARGS:{param}")
                                elif type_part == 'Body':
                                    target_fields.append(f"ARGS_POST:{param}")
                                    # target_fields.append(f"ARGS:{param}")
                            else: #参数名太奇怪的情况
                                target_fields.append("ARGS")
                                target_fields.append("REQUEST_BODY")
                        else:  # 对于Path类型的处理
                            if type_info.strip() == 'Path':
                                target_fields.append("REQUEST_FILENAME")
                            else:
                                target_fields.append("REQUEST_URI")

                    # 格式化并写入规则
                    current_regex = current_regex.lower().rstrip('\\')  # 转换为小写
                    if current_regex and target_fields:
                        fields = '|'.join(target_fields)
                        rule = (
                            f"SecRule {fields} \"@rx {current_regex}\" \\\n"
                            f"    \"id:{rule_id}, \\\n"
                            f"    deny, \\\n"
                            f"    t:lowercase, \\\n"
                            f"    t:urlDecode, \\\n"
                            f"    status:403\"\n\n"
                        )
                        print(rule)
                        outfile.write(rule)
                        rule_id += 1

                    current_regex = None
                else:
                    # 存储正则表达式，等待下一行的类型信息
                    current_regex = clean_string(line)
                    print(current_regex)

            print(f"Rules have been written to {output_filename}.")
    except Exception as e:
        print(f"Error processing file {filename}: {e}")


# 调用函数生成规则并保存到文件
input_filename = 'signature/qwen-ood/auto.txt'  # 正则表达式文件的路径
output_filename = 'signature/ood-plug.conf'  # 输出文件的路径
generate_waf_rules_withloc(input_filename, output_filename)

