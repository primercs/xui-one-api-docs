# Logs & Events API - Monitoring & Auditing

Complete documentation for logging and monitoring endpoints in the XUI.ONE Admin API.

## 📋 Overview

The Logs & Events API provides comprehensive monitoring and auditing capabilities for your IPTV panel. Track user activity, monitor connections, troubleshoot issues, and maintain security through detailed logging.

### Available Endpoints

| Endpoint | Description | Filters Available |
|----------|-------------|-------------------|
| `activity_logs` | Admin/user actions | limit, offset |
| `live_connections` | Active viewer connections | - |
| `credit_logs` | Credit transactions | user_id |
| `client_logs` | Client connection attempts | line_id |
| `user_logs` | User panel activity | user_id |
| `stream_errors` | Stream failures | stream_id |
| `watch_output` | Real-time stream monitoring | stream_id (required) |
| `system_logs` | System events | limit |
| `login_logs` | Login attempts | success (0/1) |
| `restream_logs` | Restreaming activity | - |
| `mag_events` | MAG device events | mag_id |

---

## 📊 Activity Logs

### Action: `activity_logs`

Monitor all administrative actions and changes in your panel.

**Parameters:**
- `limit` (optional) - Number of records (default: 100)
- `offset` (optional) - Pagination offset (default: 0)

**Request:**
```bash
curl "http://your-server.com/cSbuFLhp/?api_key=8D3135D30437F86EAE2FA4A2A8345000&action=activity_logs&limit=50"
```

**Response Example:**
```json
{
  "status": "STATUS_SUCCESS",
  "data": [
    {
      "id": "1",
      "user_id": "1",
      "username": "admin",
      "action": "edit_line",
      "details": "Modified line ID 123",
      "ip_address": "192.168.1.100",
      "timestamp": "1734048000"
    }
  ]
}
```

**Use Cases:**
- Audit trail for compliance
- Track configuration changes
- Monitor admin actions
- Security investigation
- Troubleshooting

---

## 🔴 Live Connections

### Action: `live_connections`

View real-time active connections to your streams.

**Request:**
```bash
curl "http://your-server.com/cSbuFLhp/?api_key=8D3135D30437F86EAE2FA4A2A8345000&action=live_connections"
```

**Response Example:**
```json
{
  "status": "STATUS_SUCCESS",
  "data": [
    {
      "line_id": "123",
      "username": "testuser",
      "stream_id": "456",
      "stream_name": "CNN HD",
      "ip_address": "203.0.113.45",
      "user_agent": "VLC/3.0.11",
      "started_at": "1734048000",
      "duration": "3600"
    }
  ]
}
```

**Use Cases:**
- Monitor concurrent viewers
- Detect connection sharing
- Track popular streams
- View geographic distribution
- Calculate bandwidth usage

---

## 💰 Credit Logs

### Action: `credit_logs`

Track credit transactions for resellers.

**Parameters:**
- `user_id` (optional) - Filter by specific user

**Request:**
```bash
curl "http://your-server.com/cSbuFLhp/?api_key=8D3135D30437F86EAE2FA4A2A8345000&action=credit_logs&user_id=5"
```

**Response Example:**
```json
{
  "status": "STATUS_SUCCESS",
  "data": [
    {
      "id": "1",
      "user_id": "5",
      "username": "reseller1",
      "action": "add_credits",
      "amount": "100.00",
      "balance_after": "500.00",
      "description": "Credit purchase",
      "timestamp": "1734048000"
    }
  ]
}
```

**Use Cases:**
- Financial auditing
- Track reseller spending
- Monitor credit flow
- Generate invoices
- Revenue reporting

---

## 📱 Client Logs

### Action: `client_logs`

Monitor client connection attempts and history.

**Parameters:**
- `line_id` (optional) - Filter by specific line

**Request:**
```bash
curl "http://your-server.com/cSbuFLhp/?api_key=8D3135D30437F86EAE2FA4A2A8345000&action=client_logs&line_id=123"
```

**Response Example:**
```json
{
  "status": "STATUS_SUCCESS",
  "data": [
    {
      "line_id": "123",
      "username": "testuser",
      "ip_address": "203.0.113.45",
      "user_agent": "Kodi/19.4",
      "connection_type": "m3u8",
      "timestamp": "1734048000"
    }
  ]
}
```

**Use Cases:**
- Track device usage
- Detect suspicious patterns
- Monitor connection types
- View client apps
- Troubleshoot connection issues

---

## 👤 User Logs

### Action: `user_logs`

Monitor user actions within the panel.

**Parameters:**
- `user_id` (optional) - Filter by specific user

**Request:**
```bash
curl "http://your-server.com/cSbuFLhp/?api_key=8D3135D30437F86EAE2FA4A2A8345000&action=user_logs"
```

**Use Cases:**
- Track reseller activity
- Monitor panel usage
- Audit user changes
- Security monitoring

---

## ⚠️ Stream Errors

### Action: `stream_errors`

View stream failure logs and error information.

**Parameters:**
- `stream_id` (optional) - Filter by specific stream

**Request:**
```bash
curl "http://your-server.com/cSbuFLhp/?api_key=8D3135D30437F86EAE2FA4A2A8345000&action=stream_errors&stream_id=456"
```

**Response Example:**
```json
{
  "status": "STATUS_SUCCESS",
  "data": [
    {
      "stream_id": "456",
      "stream_name": "CNN HD",
      "error_type": "source_offline",
      "error_message": "Connection refused to source",
      "timestamp": "1734048000",
      "duration": "120"
    }
  ]
}
```

**Use Cases:**
- Troubleshoot stream issues
- Monitor stream reliability
- Identify problematic sources
- Track downtime
- Generate uptime reports

---

## 👁️ Watch Stream Output

### Action: `watch_output`

Monitor live stream encoding details and quality.

**Parameters:**
- `stream_id` (required) - Stream ID to monitor

**Request:**
```bash
curl "http://your-server.com/cSbuFLhp/?api_key=8D3135D30437F86EAE2FA4A2A8345000&action=watch_output&stream_id=456"
```

**Response Example:**
```json
{
  "status": "STATUS_SUCCESS",
  "data": {
    "stream_id": "456",
    "bitrate": "4500 kbps",
    "resolution": "1920x1080",
    "fps": "30",
    "codec": "H.264",
    "audio_codec": "AAC",
    "buffer_health": "good"
  }
}
```

**Use Cases:**
- Monitor encoding quality
- Verify stream settings
- Diagnose playback issues
- Check bitrate stability
- Real-time troubleshooting

---

## 🖥️ System Logs

### Action: `system_logs`

View system-level events and errors.

**Parameters:**
- `limit` (optional) - Number of records (default: 100)

**Request:**
```bash
curl "http://your-server.com/cSbuFLhp/?api_key=8D3135D30437F86EAE2FA4A2A8345000&action=system_logs&limit=50"
```

**Use Cases:**
- Monitor system health
- Track errors and warnings
- Performance monitoring
- Capacity planning
- Troubleshooting

---

## 🔐 Login Logs

### Action: `login_logs`

Monitor login attempts to the panel.

**Parameters:**
- `success` (optional) - Filter by status (1 = successful, 0 = failed)

**Request:**
```bash
# Failed logins only
curl "http://your-server.com/cSbuFLhp/?api_key=8D3135D30437F86EAE2FA4A2A8345000&action=login_logs&success=0"
```

**Response Example:**
```json
{
  "status": "STATUS_SUCCESS",
  "data": [
    {
      "username": "admin",
      "ip_address": "203.0.113.45",
      "success": "0",
      "failure_reason": "Invalid password",
      "timestamp": "1734048000"
    }
  ]
}
```

**Use Cases:**
- Detect brute force attacks
- Monitor unauthorized access
- Track successful logins
- Security auditing
- IP blocking decisions

---

## 🔄 Restream Logs

### Action: `restream_logs`

Monitor reseller restreaming activity.

**Request:**
```bash
curl "http://your-server.com/cSbuFLhp/?api_key=8D3135D30437F86EAE2FA4A2A8345000&action=restream_logs"
```

**Use Cases:**
- Track restream usage
- Monitor reseller activity
- Bandwidth analysis
- Performance monitoring

---

## 📺 MAG Events

### Action: `mag_events`

View MAG device event logs.

**Parameters:**
- `mag_id` (optional) - Filter by specific MAG device

**Request:**
```bash
curl "http://your-server.com/cSbuFLhp/?api_key=8D3135D30437F86EAE2FA4A2A8345000&action=mag_events&mag_id=202"
```

**Response Example:**
```json
{
  "status": "STATUS_SUCCESS",
  "data": [
    {
      "mag_id": "202",
      "mac": "00:1A:79:XX:XX:XX",
      "event_type": "channel_change",
      "details": "Changed to channel CNN HD",
      "ip_address": "203.0.113.45",
      "timestamp": "1734048000"
    }
  ]
}
```

**Use Cases:**
- Track MAG usage
- Monitor device events
- Troubleshoot issues
- View viewing patterns

---

## 💻 Code Examples

### Python - Comprehensive Monitoring Dashboard

```python
import requests
from datetime import datetime
from collections import defaultdict

class XUIMonitor:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.api_key = api_key
    
    def _make_request(self, action, params=None):
        """Make API request"""
        request_params = {
            "api_key": self.api_key,
            "action": action
        }
        if params:
            request_params.update(params)
        
        response = requests.get(self.base_url, params=request_params)
        result = response.json()
        
        if result["status"] != "STATUS_SUCCESS":
            raise Exception(f"API Error: {result.get('error', 'Unknown')}")
        
        return result["data"]
    
    def get_live_connections(self):
        """Get current live connections"""
        return self._make_request("live_connections")
    
    def get_activity_logs(self, limit=100):
        """Get recent activity logs"""
        return self._make_request("activity_logs", {"limit": limit})
    
    def get_stream_errors(self, stream_id=None):
        """Get stream error logs"""
        params = {}
        if stream_id:
            params["stream_id"] = stream_id
        return self._make_request("stream_errors", params)
    
    def get_failed_logins(self):
        """Get failed login attempts"""
        return self._make_request("login_logs", {"success": 0})
    
    def generate_dashboard(self):
        """Generate monitoring dashboard"""
        print("=" * 60)
        print("XUI.ONE Monitoring Dashboard")
        print("=" * 60)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Live Connections
        connections = self.get_live_connections()
        print(f"🔴 Live Connections: {len(connections)}")
        
        # Group by stream
        streams = defaultdict(int)
        for conn in connections:
            streams[conn.get('stream_name', 'Unknown')] += 1
        
        print("\nTop Streams:")
        for stream, count in sorted(streams.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  • {stream}: {count} viewers")
        
        # Failed Logins
        failed_logins = self.get_failed_logins()
        if failed_logins:
            print(f"\n⚠️  Failed Login Attempts: {len(failed_logins)}")
            
            # Group by IP
            ips = defaultdict(int)
            for login in failed_logins:
                ips[login['ip_address']] += 1
            
            suspicious = [(ip, count) for ip, count in ips.items() if count > 5]
            if suspicious:
                print("\n🚨 Suspicious IPs (5+ failed attempts):")
                for ip, count in sorted(suspicious, key=lambda x: x[1], reverse=True):
                    print(f"  • {ip}: {count} attempts")
        
        # Stream Errors
        errors = self.get_stream_errors()
        if errors:
            print(f"\n⚠️  Stream Errors: {len(errors)}")
            
            # Recent errors
            recent = sorted(errors, key=lambda x: x['timestamp'], reverse=True)[:5]
            print("\nRecent Errors:")
            for error in recent:
                time = datetime.fromtimestamp(int(error['timestamp']))
                print(f"  • {error['stream_name']}: {error['error_message']} ({time.strftime('%H:%M:%S')})")
        
        print("\n" + "=" * 60)

# Usage
monitor = XUIMonitor(
    base_url="http://your-server.com/cSbuFLhp/",
    api_key="8D3135D30437F86EAE2FA4A2A8345000"
)

# Generate dashboard
monitor.generate_dashboard()
```

---

### Python - Connection Sharing Detection

```python
from collections import defaultdict
from datetime import datetime

def detect_connection_sharing(monitor):
    """Detect potential connection sharing by analyzing concurrent connections"""
    connections = monitor.get_live_connections()
    
    # Group by line_id
    lines = defaultdict(list)
    for conn in connections:
        lines[conn['line_id']].append(conn)
    
    # Find violations
    violations = []
    for line_id, conns in lines.items():
        if len(conns) > 1:
            # Check if from different IPs
            ips = set(c['ip_address'] for c in conns)
            if len(ips) > 1:
                violations.append({
                    'line_id': line_id,
                    'username': conns[0]['username'],
                    'connection_count': len(conns),
                    'unique_ips': len(ips),
                    'ips': list(ips)
                })
    
    if violations:
        print(f"⚠️  Found {len(violations)} potential sharing violations:")
        for v in violations:
            print(f"\n  Line: {v['username']} (ID: {v['line_id']})")
            print(f"  Connections: {v['connection_count']}")
            print(f"  Unique IPs: {v['unique_ips']}")
            print(f"  IPs: {', '.join(v['ips'])}")
    else:
        print("✓ No connection sharing detected")
    
    return violations
```

---

### Python - Stream Health Monitor

```python
from datetime import datetime, timedelta

def monitor_stream_health(monitor):
    """Monitor stream reliability and generate health report"""
    errors = monitor.get_stream_errors()
    
    # Group by stream
    stream_errors = defaultdict(list)
    for error in errors:
        stream_errors[error['stream_id']].append(error)
    
    print("Stream Health Report")
    print("=" * 50)
    
    for stream_id, error_list in stream_errors.items():
        if not error_list:
            continue
        
        stream_name = error_list[0].get('stream_name', f'Stream {stream_id}')
        error_count = len(error_list)
        
        # Calculate total downtime
        total_downtime = sum(int(e.get('duration', 0)) for e in error_list)
        
        # Recent errors
        recent = [e for e in error_list 
                 if int(e['timestamp']) > (datetime.now().timestamp() - 86400)]
        
        print(f"\n📺 {stream_name}")
        print(f"  Total Errors: {error_count}")
        print(f"  Errors (24h): {len(recent)}")
        print(f"  Total Downtime: {total_downtime // 60} minutes")
        
        if error_count > 10:
            print(f"  🚨 HIGH ERROR COUNT - Investigate source!")
```

---

### Python - Security Alert System

```python
def security_monitor(monitor):
    """Monitor for security issues"""
    alerts = []
    
    # Check failed logins
    failed = monitor.get_failed_logins()
    
    # Group by IP
    ip_attempts = defaultdict(int)
    for login in failed:
        ip_attempts[login['ip_address']] += 1
    
    # Alert on brute force attempts
    for ip, count in ip_attempts.items():
        if count >= 5:
            alerts.append({
                'type': 'brute_force',
                'severity': 'high' if count >= 10 else 'medium',
                'ip': ip,
                'attempts': count,
                'message': f"Brute force detected from {ip} ({count} attempts)"
            })
    
    # Check activity logs for suspicious actions
    activity = monitor.get_activity_logs(limit=100)
    
    # Alert on mass deletions
    deletes = [a for a in activity if 'delete' in a.get('action', '').lower()]
    if len(deletes) > 10:
        alerts.append({
            'type': 'mass_deletion',
            'severity': 'high',
            'count': len(deletes),
            'message': f"Mass deletion detected: {len(deletes)} items deleted recently"
        })
    
    # Display alerts
    if alerts:
        print("🚨 Security Alerts")
        print("=" * 50)
        for alert in alerts:
            severity_icon = "🔴" if alert['severity'] == 'high' else "🟡"
            print(f"\n{severity_icon} {alert['type'].upper()}")
            print(f"  {alert['message']}")
    else:
        print("✅ No security issues detected")
    
    return alerts
```

---

### PHP - Real-time Connection Monitor

```php
<?php
class XUIMonitor {
    private $baseUrl;
    private $apiKey;
    
    public function __construct($baseUrl, $apiKey) {
        $this->baseUrl = $baseUrl;
        $this->apiKey = $apiKey;
    }
    
    private function makeRequest($action, $params = []) {
        $url = $this->baseUrl . "?api_key=" . $this->apiKey . "&action=" . $action;
        
        if (!empty($params)) {
            $url .= "&" . http_build_query($params);
        }
        
        $response = file_get_contents($url);
        $result = json_decode($response, true);
        
        if ($result['status'] !== 'STATUS_SUCCESS') {
            throw new Exception("API Error: " . ($result['error'] ?? 'Unknown'));
        }
        
        return $result['data'];
    }
    
    public function getLiveConnections() {
        return $this->makeRequest('live_connections');
    }
    
    public function getConnectionStats() {
        $connections = $this->getLiveConnections();
        
        $stats = [
            'total' => count($connections),
            'by_stream' => [],
            'by_user' => [],
            'unique_ips' => []
        ];
        
        foreach ($connections as $conn) {
            // Count by stream
            $stream = $conn['stream_name'] ?? 'Unknown';
            $stats['by_stream'][$stream] = ($stats['by_stream'][$stream] ?? 0) + 1;
            
            // Count by user
            $user = $conn['username'] ?? 'Unknown';
            $stats['by_user'][$user] = ($stats['by_user'][$user] ?? 0) + 1;
            
            // Track IPs
            $stats['unique_ips'][] = $conn['ip_address'];
        }
        
        $stats['unique_ips'] = array_unique($stats['unique_ips']);
        
        return $stats;
    }
}

// Usage
$monitor = new XUIMonitor(
    "http://your-server.com/cSbuFLhp/",
    "8D3135D30437F86EAE2FA4A2A8345000"
);

$stats = $monitor->getConnectionStats();

echo "Live Connection Statistics\n";
echo "==========================\n";
echo "Total Connections: " . $stats['total'] . "\n";
echo "Unique IPs: " . count($stats['unique_ips']) . "\n\n";

echo "Top Streams:\n";
arsort($stats['by_stream']);
foreach (array_slice($stats['by_stream'], 0, 5) as $stream => $count) {
    echo "  • $stream: $count viewers\n";
}
?>
```

---

### JavaScript - Live Dashboard (Node.js)

```javascript
const fetch = require('node-fetch');

class XUIMonitor {
    constructor(baseUrl, apiKey) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
    }
    
    async makeRequest(action, params = {}) {
        const url = new URL(this.baseUrl);
        url.searchParams.append('api_key', this.apiKey);
        url.searchParams.append('action', action);
        
        for (const [key, value] of Object.entries(params)) {
            url.searchParams.append(key, value);
        }
        
        const response = await fetch(url);
        const result = await response.json();
        
        if (result.status !== 'STATUS_SUCCESS') {
            throw new Error(`API Error: ${result.error || 'Unknown'}`);
        }
        
        return result.data;
    }
    
    async getLiveConnections() {
        return this.makeRequest('live_connections');
    }
    
    async getStreamErrors() {
        return this.makeRequest('stream_errors');
    }
    
    async displayDashboard() {
        console.clear();
        console.log('═'.repeat(60));
        console.log('XUI.ONE Live Dashboard');
        console.log('═'.repeat(60));
        console.log(`Updated: ${new Date().toLocaleString()}\n`);
        
        // Live connections
        const connections = await this.getLiveConnections();
        console.log(`🔴 Live Connections: ${connections.length}`);
        
        // Stream breakdown
        const streams = connections.reduce((acc, conn) => {
            const name = conn.stream_name || 'Unknown';
            acc[name] = (acc[name] || 0) + 1;
            return acc;
        }, {});
        
        const topStreams = Object.entries(streams)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);
        
        if (topStreams.length > 0) {
            console.log('\nTop Streams:');
            topStreams.forEach(([stream, count]) => {
                console.log(`  • ${stream}: ${count} viewers`);
            });
        }
        
        // Stream errors
        const errors = await this.getStreamErrors();
        const recentErrors = errors.filter(e => 
            parseInt(e.timestamp) > (Date.now() / 1000 - 3600)
        );
        
        if (recentErrors.length > 0) {
            console.log(`\n⚠️  Recent Errors (1h): ${recentErrors.length}`);
        }
        
        console.log('\n' + '═'.repeat(60));
    }
    
    startAutoRefresh(interval = 10000) {
        this.displayDashboard();
        setInterval(() => this.displayDashboard(), interval);
    }
}

// Usage
const monitor = new XUIMonitor(
    'http://your-server.com/cSbuFLhp/',
    '8D3135D30437F86EAE2FA4A2A8345000'
);

// Auto-refresh every 10 seconds
monitor.startAutoRefresh(10000);
```

---

## 🎯 Common Use Cases

### 1. Daily Security Report

```python
def generate_security_report(monitor):
    """Generate daily security summary"""
    from datetime import datetime, timedelta
    
    yesterday = datetime.now() - timedelta(days=1)
    
    print("Daily Security Report")
    print("=" * 50)
    print(f"Date: {datetime.now().strftime('%Y-%m-%d')}")
    print()
    
    # Failed logins
    failed = monitor.get_failed_logins()
    print(f"Failed Login Attempts: {len(failed)}")
    
    # Activity summary
    activity = monitor.get_activity_logs(limit=1000)
    print(f"Admin Actions: {len(activity)}")
    
    # Connection sharing
    violations = detect_connection_sharing(monitor)
    print(f"Connection Violations: {len(violations)}")
```

### 2. Stream Performance Report

```python
def stream_performance_report(monitor):
    """Generate stream uptime and performance report"""
    errors = monitor.get_stream_errors()
    
    # Calculate uptime percentage
    total_time = 24 * 3600  # 24 hours
    downtime = sum(int(e.get('duration', 0)) for e in errors)
    uptime_pct = ((total_time - downtime) / total_time) * 100
    
    print(f"Overall Uptime: {uptime_pct:.2f}%")
    print(f"Total Downtime: {downtime // 60} minutes")
```

### 3. Real-time Alerts

```python
import time

def monitor_realtime_alerts(monitor):
    """Monitor for issues and send alerts"""
    last_check = {}
    
    while True:
        # Check for new stream errors
        errors = monitor.get_stream_errors()
        for error in errors:
            error_id = f"{error['stream_id']}_{error['timestamp']}"
            if error_id not in last_check:
                print(f"🚨 ALERT: Stream {error['stream_name']} - {error['error_message']}")
                last_check[error_id] = True
                # Send email/webhook here
        
        time.sleep(60)  # Check every minute
```

---

## 📚 Related Documentation

- [GET INFO API - Query Data](02-get-info.md)
- [Line API - Management](03-line-api.md)
- [Authentication Guide](../getting-started.md)

---

## 🆘 Need Help?

- **GitHub Issues:** [Report problems](https://github.com/worldofiptvcom/xui-one-api-docs/issues)
- **Community:** [World of IPTV Forums](https://www.worldofiptv.com)
- **Documentation:** [Getting Started Guide](../getting-started.md)
