#!/usr/bin/env python3
"""
DDoS Detection & Mitigation Real-time Dashboard
Visualizes all metrics from the C-based detection system
"""

import json
import time
import threading
from datetime import datetime
from flask import Flask, render_template_string, jsonify
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np

app = Flask(__name__)

# Global variables to store the latest data
latest_data = {
    'timestamp': 0,
    'packet_rate': 0,
    'throughput_gbps': 0,
    'entropy': 0,
    'udp_ratio': 0,
    'syn_ratio': 0,
    'detection_lead_time': 0,
    'avg_processing_latency': 0,
    'cpu_usage': 0,
    'memory_usage': 0,
    'attack_type': 'BENIGN',
    'confidence': 0,
    'unique_ips': 0,
    'is_attack': False,
    'pca_anomaly_score': 0,
    'cusum_anomaly_score': 0,
    'pca_alert': False,
    'cusum_alert': False,
    'mitigation_active': False,
    'rules_created': 0,
    'current_mitigation': 'None',
    'mitigation_effectiveness': 0,
    'attack_traffic_dropped': 0,
    'collateral_impact': 0,
    'mitigation_iteration': 0,
    'total_packets_blocked': 0,
    'top_ips': []
}

# Historical data for trends
historical_data = {
    'timestamps': [],
    'packet_rates': [],
    'entropies': [],
    'cpu_usages': [],
    'confidences': [],
    'mitigation_effectiveness': [],
    'attack_traffic_dropped': [],
    'collateral_impact': []
}

def read_live_data():
    """Read and parse the JSON data from the C program"""
    try:
        with open('ddos_live_data.json', 'r') as f:
            data = json.load(f)
            return data
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error reading data: {e}")
        return None

def update_data():
    """Background thread to continuously update data"""
    while True:
        data = read_live_data()
        if data:
            # Update latest data
            for key in latest_data:
                if key in data:
                    latest_data[key] = data[key]
            
            # Update historical data (keep last 50 points)
            current_time = datetime.fromtimestamp(data['timestamp'])
            
            if len(historical_data['timestamps']) >= 50:
                for key in historical_data:
                    historical_data[key].pop(0)
            
            historical_data['timestamps'].append(current_time)
            historical_data['packet_rates'].append(data['packet_rate'])
            historical_data['entropies'].append(data['entropy'])
            historical_data['cpu_usages'].append(data['cpu_usage'])
            historical_data['confidences'].append(data['confidence'] * 100)
            historical_data['mitigation_effectiveness'].append(data['mitigation_effectiveness'])
            historical_data['attack_traffic_dropped'].append(data['attack_traffic_dropped'])
            historical_data['collateral_impact'].append(data['collateral_impact'])
        
        time.sleep(2)  # Update every 2 seconds

def get_traffic_status_color(value, thresholds):
    """Get color based on value and thresholds"""
    if value >= thresholds['high']:
        return 'danger'
    elif value >= thresholds['medium']:
        return 'warning'
    else:
        return 'success'

def create_traffic_overview():
    """Create improved traffic overview with textual data and mini charts"""
    
    # Traffic status thresholds
    packet_rate_status = get_traffic_status_color(latest_data['packet_rate'], {'high': 5000, 'medium': 1000})
    entropy_status = get_traffic_status_color(latest_data['entropy'], {'high': 3, 'medium': 1})
    udp_status = get_traffic_status_color(latest_data['udp_ratio'] * 100, {'high': 80, 'medium': 50})
    syn_status = get_traffic_status_color(latest_data['syn_ratio'] * 100, {'high': 50, 'medium': 20})
    cpu_status = get_traffic_status_color(latest_data['cpu_usage'], {'high': 80, 'medium': 50})
    
    html_content = f'''
    <div class="row">
        <!-- Packet Statistics -->
        <div class="col-md-4 mb-3">
            <div class="card h-100">
                <div class="card-header bg-primary text-white">
                    <h6 class="mb-0"><i class="fas fa-network-wired"></i> Packet Statistics</h6>
                </div>
                <div class="card-body">
                    <div class="row text-center">
                        <div class="col-6 mb-3">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-muted small">Packet Rate</div>
                                <div class="h4 text-{packet_rate_status}">{latest_data['packet_rate']:,.0f}</div>
                                <div class="small text-muted">packets/sec</div>
                            </div>
                        </div>
                        <div class="col-6 mb-3">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-muted small">Throughput</div>
                                <div class="h4 text-info">{latest_data['throughput_gbps']:.4f}</div>
                                <div class="small text-muted">Gbps</div>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-muted small">Total Packets</div>
                                <div class="h5 text-dark">-</div>
                                <div class="small text-muted">accumulated</div>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-muted small">Unique IPs</div>
                                <div class="h5 text-dark">{latest_data['unique_ips']}</div>
                                <div class="small text-muted">sources</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Protocol Analysis -->
        <div class="col-md-4 mb-3">
            <div class="card h-100">
                <div class="card-header bg-success text-white">
                    <h6 class="mb-0"><i class="fas fa-exchange-alt"></i> Protocol Analysis</h6>
                </div>
                <div class="card-body">
                    <div class="row text-center">
                        <div class="col-6 mb-3">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-muted small">UDP Ratio</div>
                                <div class="h4 text-{udp_status}">{latest_data['udp_ratio'] * 100:.1f}%</div>
                                <div class="small text-muted">of total traffic</div>
                            </div>
                        </div>
                        <div class="col-6 mb-3">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-muted small">SYN Ratio</div>
                                <div class="h4 text-{syn_status}">{latest_data['syn_ratio'] * 100:.1f}%</div>
                                <div class="small text-muted">TCP connections</div>
                            </div>
                        </div>
                        <div class="col-12">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-muted small">Traffic Entropy</div>
                                <div class="h4 text-{entropy_status}">{latest_data['entropy']:.3f}</div>
                                <div class="small text-muted">
                                    {"(High - Distributed)" if latest_data['entropy'] > 3 else "(Low - Single Source)" if latest_data['entropy'] < 1 else "(Normal - Mixed)"}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- System Resources -->
        <div class="col-md-4 mb-3">
            <div class="card h-100">
                <div class="card-header bg-warning text-dark">
                    <h6 class="mb-0"><i class="fas fa-microchip"></i> System Resources</h6>
                </div>
                <div class="card-body">
                    <div class="row text-center">
                        <div class="col-6 mb-3">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-muted small">CPU Usage</div>
                                <div class="h4 text-{cpu_status}">{latest_data['cpu_usage']:.1f}%</div>
                                <div class="small text-muted">utilization</div>
                            </div>
                        </div>
                        <div class="col-6 mb-3">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-muted small">Memory</div>
                                <div class="h4 text-info">{latest_data['memory_usage']}</div>
                                <div class="small text-muted">MB used</div>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-muted small">Processing</div>
                                <div class="h5 text-dark">{latest_data['avg_processing_latency']:.4f}</div>
                                <div class="small text-muted">ms latency</div>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="border rounded p-2 bg-light">
                                <div class="text-muted small">Lead Time</div>
                                <div class="h5 text-dark">{latest_data['detection_lead_time']:.1f}</div>
                                <div class="small text-muted">ms detection</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Mini Charts Row -->
    <div class="row mt-3">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header py-2">
                    <h6 class="mb-0"><i class="fas fa-chart-line"></i> Packet Rate Trend</h6>
                </div>
                <div class="card-body p-2">
                    {create_mini_packet_chart()}
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="card">
                <div class="card-header py-2">
                    <h6 class="mb-0"><i class="fas fa-brain"></i> Entropy Trend</h6>
                </div>
                <div class="card-body p-2">
                    {create_mini_entropy_chart()}
                </div>
            </div>
        </div>
    </div>
    '''
    
    return html_content

def create_mini_packet_chart():
    """Create mini packet rate trend chart"""
    if len(historical_data['timestamps']) < 2:
        return "<p class='text-center text-muted my-3'>Collecting data...</p>"
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=historical_data['timestamps'],
        y=historical_data['packet_rates'],
        mode='lines',
        name='Packets/sec',
        line=dict(color='#3498db', width=2)
    ))
    
    # Add threshold lines
    fig.add_hline(y=1000, line_dash="dash", line_color="orange", annotation_text="Warning")
    fig.add_hline(y=5000, line_dash="dash", line_color="red", annotation_text="Critical")
    
    fig.update_layout(
        height=120,
        margin=dict(l=20, r=20, t=20, b=20),
        showlegend=False,
        xaxis=dict(showgrid=False, showticklabels=False),
        yaxis=dict(showgrid=True, gridcolor='lightgray')
    )
    
    return fig.to_html(full_html=False, include_plotlyjs=False)

def create_mini_entropy_chart():
    """Create mini entropy trend chart"""
    if len(historical_data['timestamps']) < 2:
        return "<p class='text-center text-muted my-3'>Collecting data...</p>"
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=historical_data['timestamps'],
        y=historical_data['entropies'],
        mode='lines',
        name='Entropy',
        line=dict(color='#27ae60', width=2)
    ))
    
    # Add threshold lines for entropy
    fig.add_hline(y=1.0, line_dash="dash", line_color="red", annotation_text="Low")
    fig.add_hline(y=3.0, line_dash="dash", line_color="green", annotation_text="High")
    
    fig.update_layout(
        height=120,
        margin=dict(l=20, r=20, t=20, b=20),
        showlegend=False,
        xaxis=dict(showgrid=False, showticklabels=False),
        yaxis=dict(showgrid=True, gridcolor='lightgray', range=[0, 5])
    )
    
    return fig.to_html(full_html=False, include_plotlyjs=False)

def create_detection_metrics():
    """Create detection metrics charts"""
    if len(historical_data['timestamps']) < 2:
        return "<div class='alert alert-info text-center'>Collecting data for trend analysis...</div>"
    
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('Packet Rate Timeline', 'Traffic Pattern Analysis',
                       'Detection Confidence', 'Anomaly Detection Scores'),
        vertical_spacing=0.1,
        horizontal_spacing=0.08
    )
    
    # Packet Rate with attack regions
    fig.add_trace(go.Scatter(
        x=historical_data['timestamps'],
        y=historical_data['packet_rates'],
        mode='lines+markers',
        name='Packet Rate',
        line=dict(color='#2980b9', width=3),
        marker=dict(size=4)
    ), row=1, col=1)
    
    # Add attack threshold area
    fig.add_hrect(y0=5000, y1=max(historical_data['packet_rates'] + [10000]), 
                 line_width=0, fillcolor="red", opacity=0.1, row=1, col=1)
    
    # Entropy analysis
    fig.add_trace(go.Scatter(
        x=historical_data['timestamps'],
        y=historical_data['entropies'],
        mode='lines+markers',
        name='Traffic Entropy',
        line=dict(color='#27ae60', width=3),
        marker=dict(size=4)
    ), row=1, col=2)
    
    # Add entropy thresholds
    fig.add_hline(y=1.0, line_dash="dash", line_color="red", 
                 annotation_text="Single Source", row=1, col=2)
    fig.add_hline(y=3.0, line_dash="dash", line_color="green", 
                 annotation_text="Distributed", row=1, col=2)
    
    # Confidence level
    fig.add_trace(go.Scatter(
        x=historical_data['timestamps'],
        y=historical_data['confidences'],
        mode='lines+markers',
        name='Confidence %',
        line=dict(color='#f39c12', width=3),
        marker=dict(size=4)
    ), row=2, col=1)
    
    # Add confidence threshold
    fig.add_hline(y=60, line_dash="dash", line_color="red", 
                 annotation_text="Attack Threshold", row=2, col=1)
    
    # Anomaly Scores
    fig.add_trace(go.Scatter(
        x=historical_data['timestamps'],
        y=[latest_data['pca_anomaly_score']] * len(historical_data['timestamps']),
        mode='lines',
        name='PCA Score',
        line=dict(color='#e74c3c', width=2)
    ), row=2, col=2)
    
    fig.add_trace(go.Scatter(
        x=historical_data['timestamps'],
        y=[latest_data['cusum_anomaly_score']] * len(historical_data['timestamps']),
        mode='lines',
        name='CUSUM Score',
        line=dict(color='#9b59b6', width=2)
    ), row=2, col=2)
    
    # Add anomaly threshold
    fig.add_hline(y=10.0, line_dash="dash", line_color="red", 
                 annotation_text="Alert Threshold", row=2, col=2)
    
    fig.update_layout(
        height=600, 
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    
    return fig.to_html(full_html=False)

def create_mitigation_metrics():
    """Create mitigation effectiveness charts"""
    if len(historical_data['timestamps']) < 2:
        return "<div class='alert alert-info text-center'>Waiting for mitigation data...</div>"
    
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('Mitigation Effectiveness Over Time', 'Attack Traffic Blocked',
                       'Collateral Impact', 'Blocking Statistics'),
        vertical_spacing=0.1
    )
    
    # Mitigation Effectiveness
    fig.add_trace(go.Scatter(
        x=historical_data['timestamps'],
        y=historical_data['mitigation_effectiveness'],
        mode='lines+markers',
        name='Effectiveness %',
        line=dict(color='#2ecc71', width=4),
        marker=dict(size=6, symbol='diamond')
    ), row=1, col=1)
    
    # Attack Traffic Dropped
    fig.add_trace(go.Scatter(
        x=historical_data['timestamps'],
        y=historical_data['attack_traffic_dropped'],
        mode='lines+markers',
        name='Traffic Dropped %',
        line=dict(color='#e74c3c', width=4),
        marker=dict(size=6)
    ), row=1, col=2)
    
    # Collateral Impact
    fig.add_trace(go.Scatter(
        x=historical_data['timestamps'],
        y=historical_data['collateral_impact'],
        mode='lines+markers',
        name='Collateral Impact %',
        line=dict(color='#f39c12', width=4),
        marker=dict(size=6)
    ), row=2, col=1)
    
    # Blocking Statistics - Use bar chart instead of gauge
    blocked_data = [latest_data['total_packets_blocked']]
    rules_data = [latest_data['rules_created']]
    
    fig.add_trace(go.Bar(
        x=['Blocked Packets'],
        y=blocked_data,
        name='Total Blocked',
        marker_color='#e74c3c',
        text=blocked_data,
        textposition='auto'
    ), row=2, col=2)
    
    fig.add_trace(go.Bar(
        x=['Active Rules'],
        y=rules_data,
        name='Active Rules',
        marker_color='#3498db',
        text=rules_data,
        textposition='auto'
    ), row=2, col=2)
    
    fig.update_layout(
        height=600, 
        showlegend=True,
        barmode='group'
    )
    
    return fig.to_html(full_html=False)

def create_attack_analysis():
    """Create attack analysis visualization"""
    if not latest_data['top_ips']:
        return "<div class='alert alert-warning text-center'>No IP traffic data available yet</div>"
    
    top_ips = latest_data['top_ips'][:8]  # Top 8 IPs
    labels = [ip['ip'] for ip in top_ips]
    percentages = [ip['percentage'] for ip in top_ips]
    counts = [ip['count'] for ip in top_ips]
    
    # Create a combined chart
    fig = make_subplots(
        rows=1, cols=2,
        specs=[[{"type": "pie"}, {"type": "bar"}]],
        subplot_titles=('Traffic Distribution by Source IP', 'Packet Volume Analysis')
    )
    
    # Pie chart with conditional coloring
    colors = ['#e74c3c' if p > 10 else '#f39c12' if p > 1 else '#27ae60' for p in percentages]
    
    fig.add_trace(go.Pie(
        labels=labels,
        values=percentages,
        hole=0.5,
        marker=dict(colors=colors),
        hoverinfo='label+percent+value',
        textinfo='label+percent',
        textposition='inside',
        name="Traffic %"
    ), row=1, col=1)
    
    # Bar chart for packet counts
    fig.add_trace(go.Bar(
        x=labels,
        y=counts,
        marker_color=colors,
        text=counts,
        textposition='auto',
        name="Packet Count"
    ), row=1, col=2)
    
    fig.update_layout(
        height=400, 
        showlegend=False,
        annotations=[
            dict(
                text="IP Traffic<br>Distribution",
                x=0.15, y=0.5,
                font_size=12,
                showarrow=False
            )
        ]
    )
    
    return fig.to_html(full_html=False)

@app.route('/')
def dashboard():
    """Main dashboard page"""
    # Determine status color and icon
    if latest_data['is_attack']:
        status_color = "danger"
        status_icon = "🔴"
        status_text = "ATTACK DETECTED"
    else:
        status_color = "success"
        status_icon = "🟢"
        status_text = "NORMAL TRAFFIC"
    
    # Mitigation status
    if latest_data['mitigation_active']:
        mitigation_status = f"ACTIVE (Iteration {latest_data['mitigation_iteration']})"
        mitigation_color = "warning"
        mitigation_icon = "🛡️"
    else:
        mitigation_status = "INACTIVE"
        mitigation_color = "secondary"
        mitigation_icon = "⚪"
    
    # Statistical alerts
    statistical_alerts = []
    if latest_data['pca_alert']:
        statistical_alerts.append("PCA Anomaly Detected")
    if latest_data['cusum_alert']:
        statistical_alerts.append("CUSUM Alert Triggered")
    
    html_template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DDoS Detection & Mitigation Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            .status-card { 
                transition: all 0.3s ease; 
                border: none;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .status-card:hover { 
                transform: translateY(-2px); 
                box-shadow: 0 4px 8px rgba(0,0,0,0.15);
            }
            .metric-value { 
                font-size: 1.4rem; 
                font-weight: bold; 
                font-family: 'Courier New', monospace;
            }
            .dashboard-header { 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 1.5rem 0;
                margin-bottom: 1.5rem;
            }
            .alert-badge {
                position: absolute;
                top: -5px;
                right: -5px;
                padding: 5px 10px;
                border-radius: 15px;
                font-size: 0.8rem;
            }
        </style>
    </head>
    <body>
        <div class="dashboard-header">
            <div class="container">
                <div class="row align-items-center">
                    <div class="col-md-8">
                        <h1><i class="fas fa-shield-alt"></i> DDoS Detection & Mitigation System</h1>
                        <p class="lead mb-0">Real-time Network Traffic Analysis and Attack Mitigation</p>
                    </div>
                    <div class="col-md-4 text-end">
                        <div class="last-update">
                            <small>Last Update: <span id="lastUpdate">{{ last_update }}</span></small>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="container">
            <!-- Status Overview -->
            <div class="row mb-4">
                <div class="col-md-4">
                    <div class="card status-card border-{{ status_color }}">
                        <div class="card-body text-center position-relative">
                            {% if statistical_alerts %}
                            <span class="alert-badge bg-warning text-dark">⚠️ {{ statistical_alerts|length }} Alerts</span>
                            {% endif %}
                            <h4 class="text-{{ status_color }}">{{ status_icon }} {{ status_text }}</h4>
                            <div class="metric-value text-{{ status_color }}">{{ "%.1f"|format(confidence) }}%</div>
                            <small class="text-muted">Detection Confidence</small>
                            <div class="mt-2">
                                <small class="text-muted">{{ attack_type }}</small>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card status-card border-{{ mitigation_color }}">
                        <div class="card-body text-center">
                            <h4 class="text-{{ mitigation_color }}">{{ mitigation_icon }} MITIGATION</h4>
                            <div class="metric-value text-{{ mitigation_color }}">{{ mitigation_status }}</div>
                            <small class="text-muted">{{ current_mitigation }}</small>
                            <div class="mt-2">
                                <div class="row">
                                    <div class="col-6">
                                        <small class="text-muted">Effectiveness</small>
                                        <div class="fw-bold text-success">{{ "%.1f"|format(mitigation_effectiveness) }}%</div>
                                    </div>
                                    <div class="col-6">
                                        <small class="text-muted">Blocked</small>
                                        <div class="fw-bold text-danger">{{ total_packets_blocked }}</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card status-card border-info">
                        <div class="card-body text-center">
                            <h4 class="text-info"><i class="fas fa-network-wired"></i> TRAFFIC SUMMARY</h4>
                            <div class="metric-value text-info">{{ "%.0f"|format(packet_rate) }} pps</div>
                            <small class="text-muted">Current Packet Rate</small>
                            <div class="mt-2">
                                <div class="row">
                                    <div class="col-6">
                                        <small class="text-muted">Unique IPs</small>
                                        <div class="fw-bold text-dark">{{ unique_ips }}</div>
                                    </div>
                                    <div class="col-6">
                                        <small class="text-muted">UDP Ratio</small>
                                        <div class="fw-bold text-warning">{{ "%.1f"|format(udp_ratio * 100) }}%</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Traffic Overview -->
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header bg-dark text-white">
                            <h5 class="mb-0"><i class="fas fa-tachometer-alt"></i> Traffic Overview & System Metrics</h5>
                        </div>
                        <div class="card-body">
                            {{ traffic_overview|safe }}
                        </div>
                    </div>
                </div>
            </div>

            <!-- Detection Metrics -->
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h5 class="mb-0"><i class="fas fa-chart-line"></i> Detection Analytics & Trends</h5>
                        </div>
                        <div class="card-body">
                            {{ detection_metrics|safe }}
                        </div>
                    </div>
                </div>
            </div>

            <!-- Mitigation Metrics -->
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header bg-success text-white">
                            <h5 class="mb-0"><i class="fas fa-shield-virus"></i> Mitigation Effectiveness & Impact</h5>
                        </div>
                        <div class="card-body">
                            {{ mitigation_metrics|safe }}
                        </div>
                    </div>
                </div>
            </div>

            <!-- Attack Analysis -->
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header bg-warning text-dark">
                            <h5 class="mb-0"><i class="fas fa-analytics"></i> Attack Source Analysis</h5>
                        </div>
                        <div class="card-body">
                            {{ attack_analysis|safe }}
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <footer class="bg-dark text-light text-center py-3 mt-5">
            <div class="container">
                <p class="mb-0">DDoS Detection System &copy; 2024 | Real-time Monitoring Dashboard | Auto-refresh: 10s</p>
            </div>
        </footer>

        <script>
            function updateTime() {
                const now = new Date();
                document.getElementById('lastUpdate').textContent = now.toLocaleString();
            }
            
            // Update time every second
            setInterval(updateTime, 1000);
            updateTime();
            
            // Auto-refresh the page every 10 seconds
            setTimeout(() => {
                window.location.reload();
            }, 10000);
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(
        html_template,
        last_update=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        status_color=status_color,
        status_icon=status_icon,
        status_text=status_text,
        mitigation_status=mitigation_status,
        mitigation_color=mitigation_color,
        mitigation_icon=mitigation_icon,
        confidence=latest_data['confidence'] * 100,
        packet_rate=latest_data['packet_rate'],
        unique_ips=latest_data['unique_ips'],
        current_mitigation=latest_data['current_mitigation'],
        attack_type=latest_data['attack_type'],
        udp_ratio=latest_data['udp_ratio'],
        mitigation_effectiveness=latest_data['mitigation_effectiveness'],
        total_packets_blocked=latest_data['total_packets_blocked'],
        statistical_alerts=statistical_alerts,
        traffic_overview=create_traffic_overview(),
        detection_metrics=create_detection_metrics(),
        mitigation_metrics=create_mitigation_metrics(),
        attack_analysis=create_attack_analysis()
    )

@app.route('/api/data')
def api_data():
    """API endpoint for JSON data"""
    return jsonify(latest_data)

@app.route('/api/history')
def api_history():
    """API endpoint for historical data"""
    return jsonify(historical_data)

if __name__ == '__main__':
    # Start background data update thread
    update_thread = threading.Thread(target=update_data, daemon=True)
    update_thread.start()
    
    print("🚀 Starting DDoS Detection Dashboard...")
    print("📊 Dashboard available at: http://localhost:5000")
    print("📈 API endpoints available at: http://localhost:5000/api/data")
    print("🔄 Auto-refreshing every 10 seconds")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
