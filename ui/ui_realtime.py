import dash
from dash import dcc, html, Input, Output, dash_table, State
import pandas as pd
import plotly.express as px
import datetime
import numpy as np
import json
import os

# 文件路径配置
# ALLOWED_FILE = "realtime_test/pdata-ood_allowed.jsonl"
# DENIED_FILE = "realtime_test/pdata-ood_denied.jsonl"
# DATA_FILE = "realtime_test/realtime_results_0.jsonl"
ALLOWED_FILE = "realtime_oodtest/pdata-ood_allowed.jsonl"
DENIED_FILE = "realtime_oodtest/pdata-ood_denied.jsonl"
DATA_FILE = "realtime_oodtest/realtime_results_0.jsonl"

# 初始化Dash应用
app = dash.Dash(__name__, external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'])
app.config.suppress_callback_exceptions = True

import hashlib
# 全局变量初始化
class GlobalState:
    def __init__(self):
        self.allowed_df = pd.DataFrame()  # 存储所有允许的请求数据
        self.denied_df = pd.DataFrame()   # 存储所有被拒绝的请求数据
        self.analysis_df = pd.DataFrame() # 存储分析数据
        self.file_status = {
            'allowed_last_pos': 0,
            'denied_last_pos': 0,
            'data_last_pos': 0
        }
        # 用字典来存储哈希值与行数据的映射
        self.allowed_hash_dict = {}
        self.denied_hash_dict = {}

    def hash_row(self, row):
        """
        计算每一行的哈希值
        将一行的所有列的值转为字符串，并计算其哈希值
        """
        row_str = ''.join(str(val) for val in row)
        return hashlib.sha256(row_str.encode('utf-8')).hexdigest()

    def update_allowed_df(self, new_data):
        # 假设 new_data 是新的数据列表
        new_data_df = pd.DataFrame(new_data)

        # 过滤新数据，确保只有唯一的数据被加入
        new_data_clean = []
        for _, row in new_data_df.iterrows():
            # 为每一行计算哈希值
            row_hash = self.hash_row(row)
            
            # 如果哈希值不在字典中，表示是新数据
            if row_hash not in self.allowed_hash_dict:
                # 将哈希值和该行数据添加到哈希值表中
                self.allowed_hash_dict[row_hash] = row
                new_data_clean.append(row)
        
        # 将新数据合并到 allowed_df 中
        new_data_clean_df = pd.DataFrame(new_data_clean)
        
        if not new_data_clean_df.empty:
            self.allowed_df = pd.concat([self.allowed_df, new_data_clean_df])

    def update_denied_df(self, new_data):
        # 假设 new_data 是新的数据列表
        new_data_df = pd.DataFrame(new_data)

        # 过滤新数据，确保只有唯一的数据被加入
        new_data_clean = []
        for _, row in new_data_df.iterrows():
            # 为每一行计算哈希值
            row_hash = self.hash_row(row)
            
            # 如果哈希值不在字典中，表示是新数据
            if row_hash not in self.denied_hash_dict:
                # 将哈希值和该行数据添加到哈希值表中
                self.denied_hash_dict[row_hash] = row
                new_data_clean.append(row)
        
        # 将新数据合并到 denied_df 中
        new_data_clean_df = pd.DataFrame(new_data_clean)
        if not new_data_clean_df.empty:
            self.denied_df = pd.concat([self.denied_df, new_data_clean_df])

global_state = GlobalState()

def parse_request(raw_request):
    """解析原始请求数据"""
    try:
        method = raw_request.get('method', '')
        url = raw_request.get('url', '')
        body = raw_request.get('body', '')
        return f"{method} {url}\n{body}".strip()
    except:
        return ""

# 自定义CSS样式
styles = {
    'header': {
        'backgroundColor': '#2c3e50',
        'padding': '1rem',
        'color': 'white',
        'display': 'flex',
        'justifyContent': 'space-between',
        'alignItems': 'center'
    },
    'metrics': {
        'padding': '2rem',
        'backgroundColor': '#f8f9fa',
        'borderBottom': '1px solid #dee2e6'
    },
    'card': {
        'padding': '1rem',
        'borderRadius': '5px',
        'boxShadow': '0 2px 5px rgba(0,0,0,0.1)',
        'backgroundColor': 'white'
    },
    'expanded-row': {
        'backgroundColor': '#f8f9fa',
        'padding': '1rem',
        'border': '1px solid #dee2e6',
        'borderTop': 'none'
    }
}

app.layout = html.Div([
    html.Div([
        html.H1("网络安全监控仪表板", style={'margin': 0}),
        html.Div([
            dcc.Input(id='search-input', type='text', placeholder='搜索请求...',
                     style={'marginRight': '1rem', 'padding': '0.5rem'}),
            html.Div(id='current-time', style={'fontSize': '0.9em'})
        ])
    ], style=styles['header']),
    
    dcc.Interval(
        id='interval-component',
        interval=6*1000,
        n_intervals=0
    ),
    
    html.Div([
        html.Div([
            html.Div([
                html.H3("总请求数", style={'color': '#3498db'}),
                html.H4(id='total-requests', style={'color': '#2ecc71'})
            ], style={'flex': 1, 'marginRight': '1rem'}),
            html.Div([
                html.H3("WAF拦截请求数", style={'color': '#3498db'}),
                html.H4(id='intercepted-requests', style={'color': '#e74c3c'})
            ], style={'flex': 1})
        ], style={**styles['card'], 'display': 'flex', 'width': '28%', 'marginRight': '1rem'}),
        
        html.Div([
            html.H3("攻击请求时间分布", style={'color': '#3498db'}),
            dcc.Graph(
                id='time-distribution',
                figure=px.line().update_layout(
                    plot_bgcolor='white',
                    paper_bgcolor='white',
                    font_color='#2c3e50'
                )
            )
        ], style={**styles['card'], 'width': '35%', 'marginRight': '1rem'}),
        
        html.Div([
            html.H3("新型恶意请求分布情况", style={'color': '#3498db'}),
            dcc.Graph(
                id='attack-distribution',
                figure=px.bar().update_layout(
                    plot_bgcolor='white',
                    paper_bgcolor='white',
                    font_color='#2c3e50',
                    height=500
                )
            )
        ], style={**styles['card'], 'width': '35%'})
    ], style={**styles['metrics'], 'display': 'flex'}),
    
    html.Div([
        dash_table.DataTable(
            id='main-table',
            columns=[
                {"name": "Request", "id": "request"},
                {"name": "Malicious Part", "id": "predict_malicious"},
                {"name": "Attack Type", "id": "prediction_result"},
                {"name": "Analysis", "id": "llm_output"},
                {"name": "详情", "id": "details"}
            ],
            data=[],
            style_header=dict(
                backgroundColor='#2c3e50',
                color='white',
                fontWeight='bold'
            ),
            style_cell={
                'textOverflow': 'ellipsis',
                'maxWidth': '200px',
                'whiteSpace': 'nowrap',
                'padding': '10px',
                'backgroundColor': 'white'
            },
            style_data_conditional=[
                {
                    'if': {'column_id': 'details'},
                    'textAlign': 'center',
                    'cursor': 'pointer',
                    'color': '#3498db',
                    'textDecoration': 'underline'
                }
            ],
            page_size=5
        )
    ], style={'padding': '2rem', 'backgroundColor': 'white'}),
    
    html.Div(id='expanded-content')
])


def read_basic_jsonl(filename, last_pos):
    """读取基础数据文件（allowed/denied）"""
    try:
        with open(filename, 'r') as f:
            f.seek(0, 2)
            file_size = f.tell()
            if last_pos > file_size:
                last_pos = 0
            f.seek(last_pos)
            new_lines = f.readlines()
            new_pos = f.tell()
            
            new_data = []
            for line in new_lines:
                try:
                    item = json.loads(line.strip())
                    raw_request = item.get('raw_request', {})
                    start_str = raw_request.get('starttimestamp') or item.get('starttimestamp')
                    new_data.append({
                        'timestamp': pd.to_datetime(start_str),
                        'status_code': item.get('status_code', 200)
                    })
                except:
                    continue
            return new_data, new_pos
    except Exception as e:
        print(f"读取文件错误 {filename}: {str(e)}")
        return [], last_pos


def read_analysis_jsonl(filename, last_pos):
    """读取分析数据文件"""
    try:
        with open(filename, 'r') as f:
            f.seek(0, 2)
            file_size = f.tell()
            if last_pos > file_size:
                last_pos = 0
            f.seek(last_pos)
            new_lines = f.readlines()
            new_pos = f.tell()
            
            new_data = []
            for line in new_lines:
                try:
                    item = json.loads(line.strip())
                    parsed = {
                        'timestamp': pd.to_datetime(item.get('starttimestamp')),
                        'request': parse_request(item.get('raw_request', {})),
                        'predict_malicious': item.get('predicted_malicious', ''),
                        'prediction_result': item.get('attack_type', '').title(),
                        'llm_output': item.get('final_analysis', '')
                    }
                    new_data.append(parsed)
                except Exception as e:
                    print(f"解析数据错误: {str(e)}")
                    continue
            return new_data, new_pos
    except Exception as e:
        print(f"读取文件错误 {filename}: {str(e)}")
        return [], last_pos

@app.callback(
    [Output('total-requests', 'children'),
     Output('intercepted-requests', 'children'),
     Output('time-distribution', 'figure'),
     Output('attack-distribution', 'figure'),
     Output('main-table', 'data')],
    [Input('interval-component', 'n_intervals'),
     Input('search-input', 'value')],
    [State('total-requests', 'children'),
     State('intercepted-requests', 'children')]
)

def update_all(n, search_value, current_total, current_intercepted):

    # 读取新数据
    new_allowed, allowed_pos = read_basic_jsonl(ALLOWED_FILE, global_state.file_status['allowed_last_pos'])
    new_denied, denied_pos = read_basic_jsonl(DENIED_FILE, global_state.file_status['denied_last_pos'])
    new_analysis, analysis_pos = read_analysis_jsonl(DATA_FILE, global_state.file_status['data_last_pos'])
    
    # 更新文件位置
    global_state.file_status.update({
        'allowed_last_pos': allowed_pos,
        'denied_last_pos': denied_pos,
        'data_last_pos': analysis_pos
    })
    
    # 合并新数据并更新total和intercepted
    if new_allowed:
        global_state.update_allowed_df(new_allowed)
    if new_denied:
        global_state.update_denied_df(new_denied)
    if new_analysis:
        global_state.analysis_df = pd.concat([global_state.analysis_df, pd.DataFrame(new_analysis)])
    
    # 更新total和intercepted
    print("allaowed:",len(global_state.allowed_df))
    print("denied:",len(global_state.denied_df))
    total = len(global_state.allowed_df) + len(global_state.denied_df)
    intercepted = len(global_state.denied_df)
    
    # 处理时间分布
    time_fig = px.line()
    if not global_state.allowed_df.empty or not global_state.denied_df.empty:
        try:
            # 合并时间数据
            # all_timestamps = pd.concat([
            #     global_state.allowed_df['timestamp'],
            #     global_state.denied_df['timestamp']
            # ]).to_frame(name='timestamp')
            all_timestamps = pd.concat([
                global_state.denied_df['timestamp'],
                global_state.analysis_df['timestamp']
            ]).to_frame(name='timestamp')
            
            # 重新采样
            # time_df = all_timestamps.resample('5T', on='timestamp').size().reset_index(name='count')
            time_df = all_timestamps.resample('10S', on='timestamp').size().reset_index(name='count')
            
            time_fig = px.line(time_df, x='timestamp', y='count', 
                             markers=True,
                             color_discrete_sequence=['#e74c3c'])
            time_fig.update_layout(
                xaxis_title="时间",
                yaxis_title="请求数量",
                plot_bgcolor='white',
                paper_bgcolor='white',
                font_color='#2c3e50',
                margin=dict(l=20, r=20, t=30, b=100),
                xaxis=dict(
                    showgrid=True,
                    gridcolor='#e0e0e0',
                    rangeslider=dict(visible=False)  # 关闭范围滑块
                ),
                yaxis=dict(
                    showgrid=True,
                    gridcolor='#e0e0e0',
                    gridwidth=1,
                    griddash='dot'
                )
            )
        except Exception as e:
            print(f"生成时间图表错误: {str(e)}")
    
    # 处理恶意请求分布（使用分析数据）
    attack_fig = px.bar()
    if not global_state.analysis_df.empty:
        try:
            attack_counts = global_state.analysis_df['prediction_result'].value_counts().reset_index()
            attack_counts.columns = ['type', 'count']
            attack_fig = px.bar(attack_counts, 
                               x='type', 
                               y='count',
                               color='type',
                               text='count',
                               height=500)
            attack_fig.update_layout(
                xaxis_title="攻击类型",
                yaxis_title="数量",
                plot_bgcolor='white',
                paper_bgcolor='white',
                font_color='#2c3e50',
                margin=dict(l=20, r=20, t=30, b=200),
                showlegend=False,
                yaxis=dict(
                    range=[0, attack_counts['count'].max() * 1.2],
                    showgrid=True,
                    gridcolor='#e0e0e0',
                    gridwidth=1,
                    griddash='dot'
                )
            )
            attack_fig.update_traces(
                textposition='outside',
                textfont_size=14,
                marker_line_width=1.5
            )
        except Exception as e:
            print(f"恶意请求处理错误: {str(e)}")
    
    # 处理表格数据（使用分析数据）
    table_data = []
    try:
        filtered_df = global_state.analysis_df.copy()
        if search_value:
            mask = filtered_df['request'].str.contains(search_value, case=False, na=False)
            filtered_df = filtered_df[mask]
        table_data = [{
            'request': row.get('request', ''),
            'predict_malicious': row.get('predict_malicious', ''),
            'prediction_result': row.get('prediction_result', ''),
            'llm_output': row.get('llm_output', ''),
            'details': '查看详情'
        } for _, row in filtered_df.iterrows()]
    except Exception as e:
        print(f"表格数据处理错误: {str(e)}")
    
    return (
        str(total), 
        str(intercepted), 
        time_fig, 
        attack_fig,
        table_data
    )



@app.callback(
    Output('current-time', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_time(n):
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# @app.callback(
#     Output('expanded-content', 'children'),
#     Input('main-table', 'active_cell'),
#     State('main-table', 'data')
# )
# def toggle_row(active_cell, rows):
#     if not active_cell or active_cell['column_id'] != 'details':
#         return None
    
#     row_data = rows[active_cell['row']]
#     return html.Div([
#         html.Div([
#             html.Div([
#                 html.Strong("Request: "),
#                 html.Pre(
#                     row_data.get('request', ''),
#                     style={
#                         'backgroundColor': '#f8f9fa',
#                         'padding': '1rem',
#                         'borderRadius': '5px',
#                         'overflowX': 'auto',
#                         'maxHeight': '300px',
#                         'whiteSpace': 'pre-wrap'
#                     }
#                 )
#             ], style={'marginBottom': '1rem'}),
#             html.Div([
#                 html.Strong("Malicious Part: "),
#                 html.Code(
#                     row_data.get('predict_malicious', ''),
#                     style={
#                         'fontSize': '1.1em',
#                         'backgroundColor': '#f8f9fa',
#                         'padding': '0.3rem 0.5rem',
#                         'borderRadius': '3px'
#                     }
#                 )
#             ], style={'marginBottom': '1rem'}),
#             html.Div([
#                 html.Strong("Analysis: "),
#                 html.Div(
#                     row_data.get('llm_output', ''),
#                     style={
#                         'whiteSpace': 'pre-wrap',
#                         'backgroundColor': '#f8f9fa',
#                         'padding': '1rem',
#                         'borderRadius': '5px'
#                     }
#                 )
#             ])
#         ], style=styles['expanded-row'])
#     ])

@app.callback(
    Output('expanded-content', 'children'),
    Input('main-table', 'active_cell'),
    [State('main-table', 'derived_virtual_data'),  # 直接使用 derived_virtual_data 作为数据源
     State('main-table', 'page_current'),          # 添加当前页码
     State('main-table', 'page_size')]             # 添加每页大小
)
def toggle_row(active_cell, derived_data, page_current, page_size):
    if not active_cell or active_cell['column_id'] != 'details':
        return None
    
    if not derived_data:
        return None
    
    # 计算实际索引（考虑分页）
    row_index = active_cell['row'] + page_current * page_size
    
    # 确保索引不越界
    if row_index >= len(derived_data):
        return None
    
    row_data = derived_data[row_index]
    
    return html.Div([
        html.Div([
            html.Div([
                html.Strong("Request: "),
                html.Pre(
                    row_data.get('request', ''),
                    style={
                        'backgroundColor': '#f8f9fa',
                        'padding': '1rem',
                        'borderRadius': '5px',
                        'overflowX': 'auto',
                        'maxHeight': '300px',
                        'whiteSpace': 'pre-wrap'
                    }
                )
            ], style={'marginBottom': '1rem'}),
            html.Div([
                html.Strong("Malicious Part: "),
                html.Code(
                    row_data.get('predict_malicious', ''),
                    style={
                        'fontSize': '1.1em',
                        'backgroundColor': '#f8f9fa',
                        'padding': '0.3rem 0.5rem',
                        'borderRadius': '3px'
                    }
                )
            ], style={'marginBottom': '1rem'}),
            html.Div([
                html.Strong("Analysis: "),
                html.Div(
                    row_data.get('llm_output', ''),
                    style={
                        'whiteSpace': 'pre-wrap',
                        'backgroundColor': '#f8f9fa',
                        'padding': '1rem',
                        'borderRadius': '5px'
                    }
                )
            ])
        ], style=styles['expanded-row'])
    ])


if __name__ == '__main__':
    app.run(debug=True, port=8050)