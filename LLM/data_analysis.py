import pandas as pd
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score, roc_curve
import numpy as np
from sklearn.metrics import classification_report, precision_recall_fscore_support
import json
import matplotlib.pyplot as plt
import os
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, ConfusionMatrixDisplay
from statistics import mean, stdev
from typing import Dict, Any

def llm_analysis_single(tasks, http_dataset, y_true, id_label, ans, output_dir):
    # 特殊缩写映射
    special_cases = {
        "cross-site scripting": "xss",
        "remote code execution": "rce",
        "path traversal": "traversal",
        "xml injection": "xxe",
    }

    # 预处理标签字典
    id_label_lower = {k: v.lower() for k, v in id_label.items()}
    for k, v in id_label_lower.items():
        if v in special_cases:
            id_label_lower[k] = special_cases[v]

    # 初始化数据结构
    y_pred = []
    report_data = []

    # 遍历每个预测结果和对应任务
    print(len(ans),len(http_dataset))
    for i, (predictedo, dataset_item) in enumerate(zip(ans, http_dataset)):
        task = tasks[i]
        predicted = predictedo.lower()
        
        # 提取最终分类结果
        if "final classification" in predicted:
            predicted = predicted.split("final classification", 1)[1].strip()
        elif "final answer:" in predicted:
            predicted = predicted.split("final answer:", 1)[1].strip()

        # 标签匹配逻辑
        match_found = False
        for k, v in id_label_lower.items():
            if v in predicted or id_label[k].lower() in predicted:
                pred_label = int(k)
                match_found = True
                break
        if not match_found:
            pred_label = len(id_label)  # 错误码

        y_pred.append(pred_label)

        # 构建请求字符串
        request = ""
        if dataset_item.method:
            request += f"Method: {dataset_item.method}\n"
        if dataset_item.url:
            request += f"URL: {dataset_item.url}\n"
        if dataset_item.body:
            request += f"Body: {dataset_item.body}\n"
        # 添加其他请求字段...

        # 构建报告条目
        if pred_label!=0 and pred_label!=9 and pred_label!=10:
            report_entry = {
                "request": request.strip(),
                "predict_malicious": task.metadata["predicted_malicious"],
                "prediction_result": id_label[str(pred_label)],
                "llm_output": task.response["assistant"],
            }
            report_data.append(report_entry)

    # 生成Excel报告
    df = pd.DataFrame(report_data)
    excel_path = os.path.join(output_dir, "classification_report.xlsx")
    df.to_excel(excel_path, index=False)

    # 生成混淆矩阵
    report_with_confusion_matrices(y_true, y_pred, len(id_label)+1, output_dir)
    return


def llm_analysis_with_confusion_matrices(y_true, id_label, ans, output_dir):
    # Special cases abbreviations mapping
    special_cases = {
        "cross-site scripting": "xss",
        "remote code execution": "rce",
        "path traversal": "traversal",
        "xml injection": "xxe",
    }

    # Preprocess id_label for efficiency and include special cases
    id_label_lower = {k: v.lower() for k, v in id_label.items()}
    # Add special case handling within the id_label dictionary
    for k, v in id_label_lower.items():
        if v in special_cases:
            id_label_lower[k] = special_cases[v]

    y_pred = []

    for predictedo in ans:
        predicted = predictedo.lower()
        if predicted == "normal":
            predicted == "normal"
        elif "final classification" in predicted:
            # 提取 "final classification" 后面的部分
            predicted = predicted.split("final classification", 1)[1].strip()
        elif "final answer:" in predicted:
            # 提取 "Final Answer:" 后面的部分
            predicted = predicted.split("final answer:", 1)[1].strip()
        
        match_found = False

        for k, v in id_label_lower.items():
            # Check both original and special case
            if v in predicted or id_label[k].lower() in predicted:
                y_pred.append(int(k))
                match_found = True
                break

        if not match_found:
            # print("An error:")
            # print(predictedo)
            y_pred.append(len(id_label))  # Use a special error code or handle differently

    # Assuming report function exists and properly handles the len(id_label)+1 case
    report_with_confusion_matrices(y_true, y_pred, len(id_label)+1, output_dir)
    return


def report_with_confusion_matrices(all_labels, all_predictions, n_class, output_dir):
    target_names = [f'Class {i}' for i in range(n_class - 1)]

    assert n_class - 1 not in all_labels
    print(type(all_predictions))  # 检查类型
    print(type(all_predictions == (n_class - 1)))  # 检查布尔数组类型
    # 确保 all_predictions 是 numpy 数组
    all_predictions = np.array(all_predictions)
    num_errors = (all_predictions == (n_class - 1)).sum()
    print(f"------ Number of errors: {num_errors} --------\n")
    
    report_str = classification_report(
        all_labels, all_predictions, zero_division=0, labels=list(range(n_class - 1)), target_names=target_names, digits=4
    )
    print(report_str)

    bin_all_labels = [1 if label > 0 else label for label in all_labels]
    bin_all_predictions = [1 if label > 0 else label for label in all_predictions]
    accuracy = accuracy_score(bin_all_labels, bin_all_predictions)
    print('Normal Accuracy: %.2f %%' % (100 * accuracy), '\n')

    # Add confusion matrix plotting
    plot_confusion_matrices(all_labels, all_predictions, target_names, output_dir)

def plot_confusion_matrices(y_true, y_pred, display_labels, output_dir):
    """
    Plot and save confusion matrices (both non-normalized and normalized) to a specified directory.

    :param y_true: List of true labels.
    :param y_pred: List of predicted labels.
    :param display_labels: List of class names for display.
    :param output_dir: Directory to save confusion matrix images.
    """
    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Compute confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=list(range(len(display_labels))))

    # Titles for different matrices
    titles_options = [
        ("Confusion matrix, without normalization", cm),
        ("Normalized confusion matrix", cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]),
    ]

    for title, matrix in titles_options:
        # Create confusion matrix display
        disp = ConfusionMatrixDisplay(confusion_matrix=matrix, display_labels=display_labels)
        disp.plot(cmap=plt.cm.Blues, ax=None)
        disp.ax_.set_title(title)
        plt.xticks(fontsize=8)  # 将字体大小调整为 8
        # Save the figure to the output directory
        filename = os.path.join(
            output_dir,
            f"{title.replace(' ', '_').replace(',', '').lower()}.png"
        )
        plt.savefig(filename, bbox_inches="tight")
        print(f"{title} saved to {filename}")

        plt.close()  # Close the figure to save memory