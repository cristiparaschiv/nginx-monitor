# NGINX Log Monitor

A real-time terminal dashboard for monitoring NGINX access and error logs. Built with Python using the Textual TUI framework, it provides an htop-like interface for visualizing web server traffic patterns, status codes, top visitors, and errors.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey.svg)

## Preview

```
╭──────────────────────────────────────────────────────────────────────────────╮
│                    NGINX Log Monitor - Real-time Dashboard                    │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─── 📊 Overview ────╮╭──── 🌐 Top IPs ────╮╭──── 📄 Top Pages ────╮
│ Total Requests: 12,847  ││ #  IP Address    Reqs ││ #  Page           Hits │
│ Unique IPs: 1,234       ││ 1  192.168.1.100 1,234││ 1  /index.html    3,456│
│ Bandwidth: 145.2 MB     ││ 2  10.0.0.50       892││ 2  /api/users     1,234│
│                         ││ 3  8.8.8.8         456││ 3  /products        892│
│ Status Codes:           ││ 4  172.16.0.1      234││ 4  /about.html      456│
│   2xx Success: 11,234   │╰──────────────────────╯╰────────────────────────╯
│   3xx Redirect: 892     │╭── 📈 Status Codes ───╮╭─── 🔧 HTTP Methods ───╮
│   4xx Client Err: 612   ││ 200 OK     ████████████││ GET  ████████████ 71.8%│
│   5xx Server Err: 109   ││ 404 Not Fnd██░░░░░░░░░││ POST ████░░░░░░░░ 16.8%│
│                         ││ 500 Error  █░░░░░░░░░░││ PUT  ██░░░░░░░░░░  6.9%│
│ Updated: 14:32:15       │╰──────────────────────╯╰────────────────────────╯
╰─────────────────────────╯
 q Quit • r Refresh • p Pause • 1/2/5 Set Interval
```

## Features

### 📊 Dashboard Panels

| Panel | Description |
|-------|-------------|
| **Overview** | Total requests, unique visitors, bandwidth usage, and status code summary |
| **Top IPs** | Most active IP addresses with request counts |
| **Top Pages** | Most frequently accessed URLs/endpoints |
| **Status Codes** | HTTP status code distribution with visual bars |
| **Hourly Traffic** | Request distribution across hours of the day |
| **HTTP Methods** | Breakdown of GET, POST, PUT, DELETE, etc. |
| **Errors** | Error log analysis with severity levels |
| **User Agents** | Browser and bot identification |
| **Bandwidth** | Data transfer by page/endpoint |

### ⚡ Key Features

- **Real-time Updates** — Auto-refreshes every 2 seconds (configurable)
- **Zero Configuration** — Works out of the box with standard NGINX log format
- **Self-contained Dependencies** — Automatically manages its own virtual environment
- **Efficient Parsing** — Uses `tail` for reading only recent log entries
- **Color-coded Output** — Visual indicators for status codes and error levels
- **Keyboard Controls** — Full keyboard navigation and control
- **Low Resource Usage** — Minimal CPU and memory footprint

## Requirements

### System Requirements

- **Operating System**: Linux or macOS
- **Python**: 3.8 or higher
- **Terminal**: Modern terminal with Unicode support (e.g., gnome-terminal, iTerm2, Alacritty)

### NGINX Log Format

The monitor expects the standard NGINX **combined** log format:

```nginx
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
```

Example log line:
```
192.168.1.100 - - [03/Jan/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0..."
```

## Installation

### Manual Installation

```bash
# Clone or download the script
git clone https://github.com/cristiparaschiv/nginx-monitor.git
cd nginx-monitor

# Option 1: Let the script manage its own venv (recommended)
./nginx-monitor.py

# Option 2: Install in your own virtual environment
python3 -m venv venv
source venv/bin/activate
pip install textual>=0.50.0 rich>=13.0.0
python nginx-monitor.py
```

### System-wide Installation

```bash
# Copy to a directory in your PATH
sudo cp nginx-monitor.py /usr/local/bin/nginx-monitor
sudo chmod +x /usr/local/bin/nginx-monitor

# Now run from anywhere
nginx-monitor
```

## Usage

### Basic Usage

```bash
# Monitor default NGINX logs
./nginx-monitor.py

# Monitor specific log files
./nginx-monitor.py -a /var/log/nginx/mysite.access.log

# Monitor both access and error logs
./nginx-monitor.py -a /var/log/nginx/access.log -e /var/log/nginx/error.log
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-a, --access-log PATH` | Path to NGINX access log | `/var/log/nginx/access.log` |
| `-e, --error-log PATH` | Path to NGINX error log | `/var/log/nginx/error.log` |
| `--clean-venv` | Remove and recreate the virtual environment | — |
| `-h, --help` | Show help message | — |

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `q` | Quit the application |
| `r` | Manual refresh |
| `p` | Pause/resume auto-refresh |
| `1` | Set refresh interval to 1 second |
| `2` | Set refresh interval to 2 seconds |
| `5` | Set refresh interval to 5 seconds |

## Configuration

### Log File Permissions

Ensure the user running the monitor has read access to the log files:

```bash
# Check current permissions
ls -la /var/log/nginx/

# Option 1: Add user to adm group (recommended)
sudo usermod -aG adm $USER
# Log out and back in for changes to take effect

# Option 2: Make logs world-readable (less secure)
sudo chmod 644 /var/log/nginx/*.log
```

### Custom Log Locations

For non-standard NGINX configurations:

```bash
# Single site
./nginx-monitor.py -a /var/log/nginx/example.com.access.log

# Docker container logs
./nginx-monitor.py -a /var/lib/docker/containers/<id>/*-json.log

# Rotated logs (monitor current file)
./nginx-monitor.py -a /var/log/nginx/access.log
```

### Virtual Environment Location

The script creates its virtual environment at:
```
~/.nginx-monitor-venv/
```

To reset if something goes wrong:
```bash
./nginx-monitor.py --clean-venv
./nginx-monitor.py  # Recreates automatically
```

## Deployment Examples

### Running as a Service (systemd)

Create `/etc/systemd/system/nginx-monitor.service`:

```ini
[Unit]
Description=NGINX Log Monitor
After=network.target

[Service]
Type=simple
User=www-data
ExecStart=/usr/local/bin/nginx-monitor -a /var/log/nginx/access.log
Restart=on-failure
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable nginx-monitor
sudo systemctl start nginx-monitor
```

### Running in tmux/screen

```bash
# Start a detached tmux session
tmux new-session -d -s nginx-monitor './nginx-monitor.py'

# Attach to view
tmux attach -t nginx-monitor

# Detach with Ctrl+B, then D
```

### Running via SSH

```bash
# Connect and run
ssh user@server -t './nginx-monitor.py'

# With custom log path
ssh user@server -t './nginx-monitor.py -a /var/log/nginx/production.access.log'
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY nginx-monitor.py .

RUN pip install textual>=0.50.0 rich>=13.0.0

ENTRYPOINT ["python", "nginx-monitor.py"]
CMD ["-a", "/logs/access.log", "-e", "/logs/error.log"]
```

```bash
docker build -t nginx-monitor .
docker run -it --rm \
  -v /var/log/nginx:/logs:ro \
  nginx-monitor
```

## Troubleshooting

### Common Issues

#### "Permission denied" when reading logs

```bash
# Add user to adm group
sudo usermod -aG adm $USER
# Log out and back in
```

#### "No module named 'textual'" or import errors

```bash
# Reset the virtual environment
./nginx-monitor.py --clean-venv
./nginx-monitor.py
```

#### Dashboard shows empty data

1. Check if the log file exists:
   ```bash
   ls -la /var/log/nginx/access.log
   ```

2. Check if the log has recent entries:
   ```bash
   tail -5 /var/log/nginx/access.log
   ```

3. Verify log format matches the expected combined format

#### Terminal display issues

- Ensure your terminal supports Unicode
- Try a different terminal emulator
- Set `TERM=xterm-256color` environment variable

#### High CPU usage

The monitor parses the last 10,000 lines by default. For very active servers:
- Increase the refresh interval (press `5` for 5 seconds)
- Use the pause feature (`p`) when not actively monitoring

### Debug Mode

To see parsing errors or issues:

```bash
# Run with Python directly to see tracebacks
python3 nginx-monitor.py -a /var/log/nginx/access.log 2>&1 | tee debug.log
```

## Log Format Compatibility

### Supported Formats

- ✅ NGINX combined (default)
- ✅ NGINX common
- ✅ Most Apache-compatible formats

### Unsupported Formats

- ❌ JSON logs (use `jq` for preprocessing)
- ❌ Custom formats with different field order

### Converting JSON Logs

If using JSON logging:

```bash
# Create a named pipe for conversion
mkfifo /tmp/nginx-access-pipe
tail -f /var/log/nginx/access.json | jq -r '"\(.remote_addr) - - [\(.time_local)] \"\(.request)\" \(.status) \(.body_bytes_sent) \"\(.http_referer)\" \"\(.http_user_agent)\""' > /tmp/nginx-access-pipe &

# Monitor the pipe
./nginx-monitor.py -a /tmp/nginx-access-pipe
```

## Contributing

Contributions are welcome! Areas for improvement:

- [ ] JSON log format support
- [ ] GeoIP integration for IP locations
- [ ] Configurable panel layout
- [ ] Export statistics to file
- [ ] Alert thresholds (e.g., error rate)
- [ ] Historical data comparison
- [ ] Multiple log file monitoring

## License

MIT License

```
Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Acknowledgments

- [Textual](https://github.com/Textualize/textual) — TUI framework for Python
- [Rich](https://github.com/Textualize/rich) — Beautiful terminal formatting
- Inspired by [htop](https://htop.dev/), [btop](https://github.com/aristocratos/btop), and [GoAccess](https://goaccess.io/)

---

**Made with ❤️ for sysadmins and DevOps engineers**
