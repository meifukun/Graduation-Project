import dash
from dash import dcc, html, Input, Output, dash_table, State
import pandas as pd
import plotly.express as px
import datetime
import numpy as np
import json
import os

# 文件路径配置
ALLOWED_FILE = "test_waf_kafka/pdata_allowed.jsonl"
DENIED_FILE = "test_waf_kafka/pdata_denied.jsonl"

# 初始化Dash应用
app = dash.Dash(__name__, external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'])
app.config.suppress_callback_exceptions = True

# 全局变量初始化
class GlobalState:
    def __init__(self):
        # 初始化为空但带结构
        self.denied_df = pd.DataFrame(columns=[
            "method", "url", "body", "case_type", "label", "caseid", "location",
            "action", "original_url", "timestamp", "status_code"
        ])
        self.file_status = {
            'allowed_last_pos': 0,
            'denied_last_pos': 0
        }

global_state = GlobalState()

def read_updates(filename, last_pos):
    """读取文件新增内容（优化版）"""
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
                    new_data.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
                    
        return new_data, new_pos
    except Exception as e:
        print(f"Error reading {filename}: {str(e)}")
        return [], last_pos

# 加载静态分析数据
try:
    df = pd.read_excel("result/qwen-iid/classification_report.xlsx").iloc[::-1].reset_index(drop=True)
    df['is_open'] = False
except Exception as e:
    print(f"Error loading Excel file: {str(e)}")
    df = pd.DataFrame()

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
        interval=5*1000,
        n_intervals=0
    ),
    
    html.Div([
        html.Div([
            html.Div([
                html.H3("总请求数", style={'color': '#3498db'}),
                html.H4(id='total-requests', style={'color': '#2ecc71'})
            ], style={'flex': 1, 'marginRight': '1rem'}),
            html.Div([
                html.H3("拦截请求数", style={'color': '#3498db'}),
                html.H4("0", id='intercepted-requests', style={'color': '#e74c3c'})
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
            html.H3("恶意请求分布", style={'color': '#3498db'}),
            dcc.Graph(
                id='attack-distribution',
                figure=px.bar().update_layout(
                    plot_bgcolor='white',
                    paper_bgcolor='white',
                    font_color='#2c3e50',
                    height=500  # 增加图表高度
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
            page_size=15
        )
    ], style={'padding': '2rem', 'backgroundColor': 'white'}),
    
    html.Div(id='expanded-content')
])

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
    total = int(current_total) if current_total and current_total.isdigit() else 0
    intercepted = int(current_intercepted) if current_intercepted and current_intercepted.isdigit() else 0
    
    # 读取新数据
    denied_data, new_denied_pos = read_updates(DENIED_FILE, global_state.file_status['denied_last_pos'])
    allowed_data, new_allowed_pos = read_updates(ALLOWED_FILE, global_state.file_status['allowed_last_pos'])
    
    # 更新文件位置
    global_state.file_status['denied_last_pos'] = new_denied_pos
    global_state.file_status['allowed_last_pos'] = new_allowed_pos
    
    # 更新指标
    total += len(denied_data) + len(allowed_data)
    intercepted += len(denied_data)
    
    # 处理时间分布
    if denied_data:
        try:
            new_denied = pd.DataFrame(denied_data)
            
            # 规范时间格式
            if 'timestamp' in new_denied:
                new_denied['timestamp'] = pd.to_datetime(new_denied['timestamp'], errors='coerce')
                new_denied = new_denied.dropna(subset=['timestamp'])
            
            # 合并数据时指定列（防止字段不一致）
            base_cols = ['timestamp', 'url', 'method', 'status_code']
            new_denied = new_denied.reindex(columns=base_cols + list(new_denied.columns.difference(base_cols)))
            
            global_state.denied_df = pd.concat([
                global_state.denied_df[new_denied.columns], 
                new_denied
            ])
            
            # 按关键字段去重
            global_state.denied_df = global_state.denied_df.drop_duplicates(
                subset=['timestamp', 'url', 'method'],
                keep='last'
            ).sort_values('timestamp')
            
            # 清理7天前的数据
            cutoff = pd.Timestamp.now() - pd.Timedelta(days=7)
            global_state.denied_df = global_state.denied_df[global_state.denied_df['timestamp'] >= cutoff]

        except Exception as e:
            print(f"时间数据处理错误: {str(e)}")
    
    time_fig = px.line()
    if not global_state.denied_df.empty:
        try:
            time_range = global_state.denied_df['timestamp'].max() - global_state.denied_df['timestamp'].min()
            
            if time_range <= pd.Timedelta(hours=1):
                freq = '1T'
            elif time_range <= pd.Timedelta(hours=6):
                freq = '5T'
            elif time_range <= pd.Timedelta(days=1):
                freq = '1H'
            else:
                freq = '1D'
                
            time_df = global_state.denied_df.resample(freq, on='timestamp').size().reset_index(name='count')
            
            time_fig = px.line(time_df, x='timestamp', y='count', 
                             markers=True,
                             color_discrete_sequence=['#e74c3c'])
            
            # 修复布局配置
            time_fig.update_layout(
                xaxis_title="时间",
                yaxis_title="攻击请求数量",
                plot_bgcolor='white',
                paper_bgcolor='white',
                font_color='#2c3e50',
                margin=dict(l=20, r=20, t=30, b=100),
                xaxis=dict(
                    showgrid=True,
                    gridcolor='#e0e0e0',
                    rangeslider=dict(visible=False)
                ),
                yaxis=dict(
                    showgrid=True,
                    gridcolor='#e0e0e0',
                    gridwidth=1,
                    griddash='dot'  # 添加虚线网格
                )
            )
        except Exception as e:
            print(f"生成时间图表错误: {str(e)}")
    
    # 处理恶意请求分布
    attack_fig = px.bar()
    if not df.empty and 'prediction_result' in df.columns:
        try:
            attack_counts = df['prediction_result'].value_counts().reset_index()
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
                    griddash='dot'  # 添加虚线网格
                )
            )
            attack_fig.update_traces(
                textposition='outside',
                textfont_size=14,
                marker_line_width=1.5
            )
        except Exception as e:
            print(f"恶意请求处理错误: {str(e)}")
    
    # 处理表格数据
    table_data = []
    try:
        filtered_df = df.copy()
        if search_value:
            filtered_df = filtered_df[filtered_df['request'].str.contains(search_value, case=False, na=False)]
        table_data = [{**row, 'details': '查看详情'} for row in filtered_df.to_dict('records')]
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

@app.callback(
    Output('expanded-content', 'children'),
    Input('main-table', 'active_cell'),
    State('main-table', 'data')
)
def toggle_row(active_cell, rows):
    if not active_cell or active_cell['column_id'] != 'details':
        return None
    
    row_data = rows[active_cell['row']]
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
                        'overflowX': 'auto',  # 恢复横向滚动
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