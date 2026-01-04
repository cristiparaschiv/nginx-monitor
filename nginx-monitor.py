#!/usr/bin/env python3
"""
NGINX Log Monitor - Real-time TUI Dashboard
A terminal-based nginx log analyzer with live updates
"""

import os
import re
import sys
import subprocess
import shutil
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
# Dependency Management
# ═══════════════════════════════════════════════════════════════════════════════

REQUIRED_PACKAGES = [
    ("textual", "0.50.0"),
    ("rich", "13.0.0"),
]

def get_venv_path():
    """Get path for virtual environment"""
    return Path.home() / ".nginx-monitor-venv"

def setup_venv():
    """Create and setup virtual environment if needed"""
    venv_path = get_venv_path()
    venv_python = venv_path / "bin" / "python"
    
    if not venv_python.exists():
        print(f"Creating virtual environment at {venv_path}...")
        subprocess.check_call([sys.executable, "-m", "venv", str(venv_path)])
        
        # Install packages in venv
        pip_path = venv_path / "bin" / "pip"
        print("Installing required packages...")
        for package, min_version in REQUIRED_PACKAGES:
            subprocess.check_call([
                str(pip_path), "install", "-q", f"{package}>={min_version}"
            ])
        print("Setup complete!\n")
    
    return str(venv_python)

def check_imports():
    """Check if we can import required modules"""
    try:
        from textual.app import App, ComposeResult
        from textual.widgets import Header, Footer, Static
        return True
    except ImportError:
        return False

def relaunch_in_venv():
    """Relaunch script using venv python"""
    venv_python = setup_venv()
    os.execv(venv_python, [venv_python] + sys.argv)

# Check if we need to use venv
if not check_imports():
    print("System packages are outdated. Setting up isolated environment...")
    relaunch_in_venv()

# ═══════════════════════════════════════════════════════════════════════════════
# Now safe to import
# ═══════════════════════════════════════════════════════════════════════════════

import time
import argparse
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Optional

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Static, DataTable, Label, TabbedContent, TabPane
from textual.reactive import reactive
from textual.binding import Binding
from rich.text import Text
from rich.style import Style
from rich.table import Table
from rich.panel import Panel
from rich.console import Console, Group
from rich import box


# ═══════════════════════════════════════════════════════════════════════════════
# Log Parser
# ═══════════════════════════════════════════════════════════════════════════════

class NginxLogParser:
    """Parse and analyze nginx log files"""
    
    # Common nginx combined log format regex
    LOG_PATTERN = re.compile(
        r'(?P<ip>\S+)\s+'                      # IP address
        r'\S+\s+'                               # ident
        r'\S+\s+'                               # user
        r'\[(?P<time>[^\]]+)\]\s+'              # timestamp
        r'"(?P<method>\S+)\s+'                  # HTTP method
        r'(?P<path>\S+)\s+'                     # path
        r'(?P<protocol>[^"]+)"\s+'              # protocol
        r'(?P<status>\d+)\s+'                   # status code
        r'(?P<size>\S+)\s+'                     # response size
        r'"(?P<referer>[^"]*)"\s+'              # referer
        r'"(?P<agent>[^"]*)"'                   # user agent
    )
    
    def __init__(self, access_log: str, error_log: str, tail_lines: int = 10000):
        self.access_log = access_log
        self.error_log = error_log
        self.tail_lines = tail_lines
        self.last_parse_time = None
        self._cache = {}
        
    def _read_log_tail(self, filepath: str, lines: int) -> List[str]:
        """Read last N lines from log file efficiently"""
        if not os.path.exists(filepath):
            return []
        try:
            result = subprocess.run(
                ['tail', '-n', str(lines), filepath],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip().split('\n') if result.stdout.strip() else []
        except Exception:
            return []
    
    def _parse_access_line(self, line: str) -> Optional[Dict]:
        """Parse a single access log line"""
        match = self.LOG_PATTERN.match(line)
        if match:
            data = match.groupdict()
            # Convert size to int
            try:
                data['size'] = int(data['size']) if data['size'] != '-' else 0
            except ValueError:
                data['size'] = 0
            # Convert status to int
            try:
                data['status'] = int(data['status'])
            except ValueError:
                data['status'] = 0
            return data
        return None
    
    def parse_access_log(self) -> List[Dict]:
        """Parse access log and return list of parsed entries"""
        lines = self._read_log_tail(self.access_log, self.tail_lines)
        entries = []
        for line in lines:
            if line:
                parsed = self._parse_access_line(line)
                if parsed:
                    entries.append(parsed)
        return entries
    
    def get_stats(self) -> Dict:
        """Get comprehensive statistics from logs"""
        entries = self.parse_access_log()
        self.last_parse_time = datetime.now()
        
        if not entries:
            return self._empty_stats()
        
        # Counters
        ips = Counter()
        pages = Counter()
        status_codes = Counter()
        methods = Counter()
        referers = Counter()
        agents = Counter()
        hourly = Counter()
        bandwidth_by_page = defaultdict(int)
        requests_by_page = defaultdict(int)
        
        total_bandwidth = 0
        
        for entry in entries:
            ips[entry['ip']] += 1
            pages[entry['path']] += 1
            status_codes[entry['status']] += 1
            methods[entry['method']] += 1
            
            if entry['referer'] and entry['referer'] != '-':
                referers[entry['referer']] += 1
            
            # Simplify user agent
            agent = self._simplify_agent(entry['agent'])
            agents[agent] += 1
            
            # Extract hour from timestamp
            try:
                hour = entry['time'].split(':')[1]
                hourly[hour] += 1
            except (IndexError, AttributeError):
                pass
            
            # Bandwidth
            size = entry['size']
            total_bandwidth += size
            bandwidth_by_page[entry['path']] += size
            requests_by_page[entry['path']] += 1
        
        # Calculate status categories
        success = sum(c for s, c in status_codes.items() if 200 <= s < 300)
        redirect = sum(c for s, c in status_codes.items() if 300 <= s < 400)
        client_err = sum(c for s, c in status_codes.items() if 400 <= s < 500)
        server_err = sum(c for s, c in status_codes.items() if 500 <= s < 600)
        
        # Parse error log
        error_stats = self._parse_error_log()
        
        return {
            'total_requests': len(entries),
            'unique_ips': len(ips),
            'total_bandwidth': total_bandwidth,
            'top_ips': ips.most_common(15),
            'top_pages': pages.most_common(15),
            'status_codes': status_codes.most_common(10),
            'status_summary': {
                '2xx': success,
                '3xx': redirect,
                '4xx': client_err,
                '5xx': server_err
            },
            'methods': methods.most_common(10),
            'top_referers': referers.most_common(10),
            'top_agents': agents.most_common(10),
            'hourly': dict(sorted(hourly.items())),
            'bandwidth_by_page': sorted(
                [(p, bandwidth_by_page[p], requests_by_page[p]) for p in bandwidth_by_page],
                key=lambda x: x[1], reverse=True
            )[:15],
            'errors': error_stats,
            'parse_time': self.last_parse_time
        }
    
    def _simplify_agent(self, agent: str) -> str:
        """Simplify user agent string to browser/bot name"""
        agent_lower = agent.lower()
        if 'googlebot' in agent_lower:
            return 'Googlebot'
        elif 'bingbot' in agent_lower:
            return 'Bingbot'
        elif 'bot' in agent_lower or 'crawler' in agent_lower or 'spider' in agent_lower:
            return 'Other Bot'
        elif 'curl' in agent_lower:
            return 'curl'
        elif 'wget' in agent_lower:
            return 'wget'
        elif 'python' in agent_lower:
            return 'Python'
        elif 'edge' in agent_lower or 'edg/' in agent_lower:
            return 'Edge'
        elif 'firefox' in agent_lower:
            return 'Firefox'
        elif 'chrome' in agent_lower:
            return 'Chrome'
        elif 'safari' in agent_lower:
            return 'Safari'
        elif 'opera' in agent_lower:
            return 'Opera'
        elif agent == '-' or not agent:
            return 'Empty'
        else:
            return agent[:30] + '...' if len(agent) > 30 else agent
    
    def _parse_error_log(self) -> Dict:
        """Parse error log for statistics"""
        lines = self._read_log_tail(self.error_log, 1000)
        
        levels = Counter()
        recent_errors = []
        error_messages = Counter()
        
        level_pattern = re.compile(r'\[(emerg|alert|crit|error|warn|notice|info|debug)\]')
        
        for line in lines:
            if not line:
                continue
            match = level_pattern.search(line)
            if match:
                level = match.group(1)
                levels[level] += 1
                
                if level in ('emerg', 'alert', 'crit', 'error'):
                    # Extract error message
                    msg = line[match.end():].strip()[:80]
                    error_messages[msg] += 1
                    if level in ('emerg', 'alert', 'crit'):
                        recent_errors.append((level, line[:120]))
        
        return {
            'levels': dict(levels),
            'recent_critical': recent_errors[-5:],
            'common_errors': error_messages.most_common(10)
        }
    
    def _empty_stats(self) -> Dict:
        """Return empty stats structure"""
        return {
            'total_requests': 0,
            'unique_ips': 0,
            'total_bandwidth': 0,
            'top_ips': [],
            'top_pages': [],
            'status_codes': [],
            'status_summary': {'2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0},
            'methods': [],
            'top_referers': [],
            'top_agents': [],
            'hourly': {},
            'bandwidth_by_page': [],
            'errors': {'levels': {}, 'recent_critical': [], 'common_errors': []},
            'parse_time': datetime.now()
        }


# ═══════════════════════════════════════════════════════════════════════════════
# TUI Widgets
# ═══════════════════════════════════════════════════════════════════════════════

def format_bytes(b: int) -> str:
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


class StatsPanel(Static):
    """Widget displaying summary statistics"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stats = None
    
    def update_stats(self, stats: Dict):
        self.stats = stats
        self.refresh()
    
    def render(self) -> Panel:
        if not self.stats:
            return Panel("Loading...", title="📊 Overview", border_style="blue")
        
        s = self.stats
        status = s['status_summary']
        
        # Create summary text
        lines = []
        lines.append(f"[bold cyan]Total Requests:[/] {s['total_requests']:,}")
        lines.append(f"[bold cyan]Unique IPs:[/] {s['unique_ips']:,}")
        lines.append(f"[bold cyan]Bandwidth:[/] {format_bytes(s['total_bandwidth'])}")
        lines.append("")
        lines.append("[bold]Status Codes:[/]")
        lines.append(f"  [green]2xx Success:[/] {status['2xx']:,}")
        lines.append(f"  [yellow]3xx Redirect:[/] {status['3xx']:,}")
        lines.append(f"  [red]4xx Client Err:[/] {status['4xx']:,}")
        lines.append(f"  [bold red]5xx Server Err:[/] {status['5xx']:,}")
        lines.append("")
        
        # Request rate (approximate)
        if s['parse_time']:
            lines.append(f"[dim]Updated: {s['parse_time'].strftime('%H:%M:%S')}[/]")
        
        return Panel(
            "\n".join(lines),
            title="📊 Overview",
            border_style="blue",
            box=box.ROUNDED
        )


class TopIPsPanel(Static):
    """Widget displaying top IP addresses"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stats = None
    
    def update_stats(self, stats: Dict):
        self.stats = stats
        self.refresh()
    
    def render(self) -> Panel:
        if not self.stats:
            return Panel("Loading...", title="🌐 Top IPs", border_style="green")
        
        table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold")
        table.add_column("#", style="dim", width=3)
        table.add_column("IP Address", style="cyan")
        table.add_column("Requests", justify="right", style="green")
        
        for i, (ip, count) in enumerate(self.stats['top_ips'][:10], 1):
            table.add_row(str(i), ip, f"{count:,}")
        
        return Panel(table, title="🌐 Top IPs", border_style="green", box=box.ROUNDED)


class TopPagesPanel(Static):
    """Widget displaying top pages"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stats = None
    
    def update_stats(self, stats: Dict):
        self.stats = stats
        self.refresh()
    
    def render(self) -> Panel:
        if not self.stats:
            return Panel("Loading...", title="📄 Top Pages", border_style="yellow")
        
        table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold")
        table.add_column("#", style="dim", width=3)
        table.add_column("Page/URI", style="cyan", overflow="ellipsis", max_width=40)
        table.add_column("Hits", justify="right", style="yellow")
        
        for i, (page, count) in enumerate(self.stats['top_pages'][:10], 1):
            display_page = page if len(page) <= 40 else page[:37] + "..."
            table.add_row(str(i), display_page, f"{count:,}")
        
        return Panel(table, title="📄 Top Pages", border_style="yellow", box=box.ROUNDED)


class StatusCodesPanel(Static):
    """Widget displaying status code distribution"""
    
    STATUS_COLORS = {
        2: "green",
        3: "yellow", 
        4: "red",
        5: "bold red"
    }
    
    STATUS_DESC = {
        200: "OK", 201: "Created", 204: "No Content",
        301: "Moved", 302: "Found", 304: "Not Modified",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 405: "Method Not Allowed", 429: "Too Many Req",
        500: "Server Error", 502: "Bad Gateway", 503: "Unavailable", 504: "Timeout"
    }
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stats = None
    
    def update_stats(self, stats: Dict):
        self.stats = stats
        self.refresh()
    
    def render(self) -> Panel:
        if not self.stats:
            return Panel("Loading...", title="📈 Status Codes", border_style="magenta")
        
        table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold")
        table.add_column("Code", width=5)
        table.add_column("Description", width=14)
        table.add_column("Count", justify="right", width=8)
        table.add_column("Bar", width=15)
        
        total = self.stats['total_requests'] or 1
        max_count = max((c for _, c in self.stats['status_codes']), default=1)
        
        for status, count in self.stats['status_codes'][:8]:
            color = self.STATUS_COLORS.get(status // 100, "white")
            desc = self.STATUS_DESC.get(status, "")
            bar_len = int((count / max_count) * 12)
            bar = "█" * bar_len + "░" * (12 - bar_len)
            
            table.add_row(
                f"[{color}]{status}[/]",
                desc,
                f"{count:,}",
                f"[{color}]{bar}[/]"
            )
        
        return Panel(table, title="📈 Status Codes", border_style="magenta", box=box.ROUNDED)


class HourlyPanel(Static):
    """Widget displaying hourly traffic distribution"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stats = None
    
    def update_stats(self, stats: Dict):
        self.stats = stats
        self.refresh()
    
    def render(self) -> Panel:
        if not self.stats or not self.stats['hourly']:
            return Panel("Loading...", title="⏰ Hourly Traffic", border_style="cyan")
        
        hourly = self.stats['hourly']
        max_val = max(hourly.values()) if hourly else 1
        
        lines = []
        for hour in sorted(hourly.keys()):
            count = hourly[hour]
            bar_len = int((count / max_val) * 20)
            bar = "█" * bar_len
            lines.append(f"[dim]{hour}:00[/] [cyan]{bar}[/] {count:,}")
        
        return Panel(
            "\n".join(lines) if lines else "No data",
            title="⏰ Hourly Traffic",
            border_style="cyan",
            box=box.ROUNDED
        )


class MethodsPanel(Static):
    """Widget displaying HTTP methods"""
    
    METHOD_COLORS = {
        "GET": "green",
        "POST": "yellow",
        "PUT": "blue",
        "DELETE": "red",
        "PATCH": "magenta",
        "HEAD": "cyan",
        "OPTIONS": "dim"
    }
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stats = None
    
    def update_stats(self, stats: Dict):
        self.stats = stats
        self.refresh()
    
    def render(self) -> Panel:
        if not self.stats:
            return Panel("Loading...", title="🔧 Methods", border_style="blue")
        
        lines = []
        total = self.stats['total_requests'] or 1
        
        for method, count in self.stats['methods'][:6]:
            color = self.METHOD_COLORS.get(method, "white")
            pct = (count / total) * 100
            bar_len = int(pct / 5)
            bar = "█" * bar_len
            lines.append(f"[{color}]{method:7}[/] {bar:20} {count:>6,} ({pct:.1f}%)")
        
        return Panel(
            "\n".join(lines) if lines else "No data",
            title="🔧 HTTP Methods",
            border_style="blue",
            box=box.ROUNDED
        )


class ErrorsPanel(Static):
    """Widget displaying error information"""
    
    LEVEL_COLORS = {
        "emerg": "bold red reverse",
        "alert": "bold red",
        "crit": "red",
        "error": "red",
        "warn": "yellow",
        "notice": "cyan",
        "info": "green",
        "debug": "dim"
    }
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stats = None
    
    def update_stats(self, stats: Dict):
        self.stats = stats
        self.refresh()
    
    def render(self) -> Panel:
        if not self.stats:
            return Panel("Loading...", title="⚠️ Errors", border_style="red")
        
        errors = self.stats.get('errors', {})
        levels = errors.get('levels', {})
        
        lines = []
        
        # Error level counts
        lines.append("[bold]Error Levels:[/]")
        for level in ['emerg', 'alert', 'crit', 'error', 'warn', 'notice', 'info', 'debug']:
            if level in levels:
                color = self.LEVEL_COLORS.get(level, "white")
                lines.append(f"  [{color}]{level:8}[/] {levels[level]:,}")
        
        if not levels:
            lines.append("  [dim]No errors found[/]")
        
        # Recent critical errors
        recent = errors.get('recent_critical', [])
        if recent:
            lines.append("")
            lines.append("[bold red]Recent Critical:[/]")
            for level, msg in recent[-3:]:
                lines.append(f"  [red]{msg[:60]}...[/]")
        
        return Panel(
            "\n".join(lines),
            title="⚠️  Errors",
            border_style="red",
            box=box.ROUNDED
        )


class UserAgentsPanel(Static):
    """Widget displaying top user agents"""
    
    AGENT_ICONS = {
        "Chrome": "🌐",
        "Firefox": "🦊",
        "Safari": "🧭",
        "Edge": "🔷",
        "Googlebot": "🤖",
        "Bingbot": "🤖",
        "Other Bot": "🤖",
        "curl": "⌨️",
        "wget": "⌨️",
        "Python": "🐍"
    }
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stats = None
    
    def update_stats(self, stats: Dict):
        self.stats = stats
        self.refresh()
    
    def render(self) -> Panel:
        if not self.stats:
            return Panel("Loading...", title="👤 User Agents", border_style="green")
        
        lines = []
        for agent, count in self.stats['top_agents'][:8]:
            icon = self.AGENT_ICONS.get(agent, "•")
            lines.append(f"{icon} [cyan]{agent:20}[/] {count:>6,}")
        
        return Panel(
            "\n".join(lines) if lines else "No data",
            title="👤 User Agents",
            border_style="green",
            box=box.ROUNDED
        )


class BandwidthPanel(Static):
    """Widget displaying bandwidth by page"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stats = None
    
    def update_stats(self, stats: Dict):
        self.stats = stats
        self.refresh()
    
    def render(self) -> Panel:
        if not self.stats:
            return Panel("Loading...", title="📊 Bandwidth", border_style="yellow")
        
        table = Table(box=box.SIMPLE, expand=True, show_header=True, header_style="bold")
        table.add_column("Page", overflow="ellipsis", max_width=30)
        table.add_column("Size", justify="right", width=10)
        table.add_column("Reqs", justify="right", width=6)
        
        for page, size, reqs in self.stats['bandwidth_by_page'][:8]:
            display_page = page if len(page) <= 30 else page[:27] + "..."
            table.add_row(display_page, format_bytes(size), f"{reqs:,}")
        
        return Panel(table, title="📊 Bandwidth by Page", border_style="yellow", box=box.ROUNDED)


class ReferersPanel(Static):
    """Widget displaying top referers"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stats = None
    
    def update_stats(self, stats: Dict):
        self.stats = stats
        self.refresh()
    
    def render(self) -> Panel:
        if not self.stats:
            return Panel("Loading...", title="🔗 Referers", border_style="magenta")
        
        lines = []
        for ref, count in self.stats['top_referers'][:8]:
            # Truncate long referers
            display_ref = ref if len(ref) <= 40 else ref[:37] + "..."
            lines.append(f"[cyan]{display_ref:42}[/] {count:>5,}")
        
        if not lines:
            lines.append("[dim]No external referers[/]")
        
        return Panel(
            "\n".join(lines),
            title="🔗 Top Referers",
            border_style="magenta",
            box=box.ROUNDED
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Main Application
# ═══════════════════════════════════════════════════════════════════════════════

class NginxMonitorApp(App):
    """Main TUI Application"""
    
    CSS = """
    Screen {
        layout: grid;
        grid-size: 3 3;
        grid-gutter: 1;
        padding: 1;
    }
    
    .panel {
        height: 100%;
    }
    
    #stats-panel {
        column-span: 1;
        row-span: 1;
    }
    
    #ips-panel {
        column-span: 1;
        row-span: 1;
    }
    
    #pages-panel {
        column-span: 1;
        row-span: 1;
    }
    
    #status-panel {
        column-span: 1;
        row-span: 1;
    }
    
    #hourly-panel {
        column-span: 1;
        row-span: 1;
    }
    
    #methods-panel {
        column-span: 1;
        row-span: 1;
    }
    
    #errors-panel {
        column-span: 1;
        row-span: 1;
    }
    
    #agents-panel {
        column-span: 1;
        row-span: 1;
    }
    
    #bandwidth-panel {
        column-span: 1;
        row-span: 1;
    }
    
    Header {
        dock: top;
        height: 1;
    }
    
    Footer {
        dock: bottom;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("p", "pause", "Pause"),
        Binding("1", "set_refresh(1)", "1s"),
        Binding("2", "set_refresh(2)", "2s"),
        Binding("5", "set_refresh(5)", "5s"),
    ]
    
    TITLE = "NGINX Log Monitor"
    SUB_TITLE = "Real-time Dashboard"
    
    paused = reactive(False)
    refresh_interval = reactive(2.0)
    
    def __init__(self, access_log: str, error_log: str, **kwargs):
        super().__init__(**kwargs)
        self.parser = NginxLogParser(access_log, error_log)
        self.stats = None
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield StatsPanel(id="stats-panel", classes="panel")
        yield TopIPsPanel(id="ips-panel", classes="panel")
        yield TopPagesPanel(id="pages-panel", classes="panel")
        yield StatusCodesPanel(id="status-panel", classes="panel")
        yield HourlyPanel(id="hourly-panel", classes="panel")
        yield MethodsPanel(id="methods-panel", classes="panel")
        yield ErrorsPanel(id="errors-panel", classes="panel")
        yield UserAgentsPanel(id="agents-panel", classes="panel")
        yield BandwidthPanel(id="bandwidth-panel", classes="panel")
        yield Footer()
    
    def on_mount(self) -> None:
        """Start the refresh timer on mount"""
        self.refresh_data()
        self.set_interval(self.refresh_interval, self.auto_refresh)
    
    def auto_refresh(self) -> None:
        """Auto refresh callback"""
        if not self.paused:
            self.refresh_data()
    
    def refresh_data(self) -> None:
        """Refresh all panels with new data"""
        self.stats = self.parser.get_stats()
        
        # Update all panels
        self.query_one("#stats-panel", StatsPanel).update_stats(self.stats)
        self.query_one("#ips-panel", TopIPsPanel).update_stats(self.stats)
        self.query_one("#pages-panel", TopPagesPanel).update_stats(self.stats)
        self.query_one("#status-panel", StatusCodesPanel).update_stats(self.stats)
        self.query_one("#hourly-panel", HourlyPanel).update_stats(self.stats)
        self.query_one("#methods-panel", MethodsPanel).update_stats(self.stats)
        self.query_one("#errors-panel", ErrorsPanel).update_stats(self.stats)
        self.query_one("#agents-panel", UserAgentsPanel).update_stats(self.stats)
        self.query_one("#bandwidth-panel", BandwidthPanel).update_stats(self.stats)
    
    def action_refresh(self) -> None:
        """Manual refresh action"""
        self.refresh_data()
        self.notify("Data refreshed!")
    
    def action_pause(self) -> None:
        """Toggle pause"""
        self.paused = not self.paused
        status = "paused" if self.paused else "resumed"
        self.notify(f"Auto-refresh {status}")
    
    def action_set_refresh(self, interval: int) -> None:
        """Set refresh interval"""
        self.refresh_interval = float(interval)
        self.notify(f"Refresh interval: {interval}s")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="NGINX Log Monitor - Real-time TUI Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s
    %(prog)s -a /var/log/nginx/mysite.access.log
    %(prog)s -a access.log -e error.log

Keyboard Shortcuts:
    q       Quit
    r       Manual refresh
    p       Pause/resume auto-refresh
    1/2/5   Set refresh interval (seconds)
        """
    )
    
    parser.add_argument(
        "-a", "--access-log",
        default="/var/log/nginx/access.log",
        help="Path to nginx access log (default: /var/log/nginx/access.log)"
    )
    
    parser.add_argument(
        "-e", "--error-log",
        default="/var/log/nginx/error.log",
        help="Path to nginx error log (default: /var/log/nginx/error.log)"
    )
    
    parser.add_argument(
        "--clean-venv",
        action="store_true",
        help="Remove and recreate the virtual environment"
    )
    
    args = parser.parse_args()
    
    # Handle --clean-venv
    if args.clean_venv:
        venv_path = get_venv_path()
        if venv_path.exists():
            print(f"Removing {venv_path}...")
            shutil.rmtree(venv_path)
            print("Done. Run the script again to recreate.")
            sys.exit(0)
    
    # Check if log file exists
    if not os.path.exists(args.access_log):
        print(f"Warning: Access log not found: {args.access_log}")
        print("The dashboard will show empty data until the log file is available.")
    
    app = NginxMonitorApp(args.access_log, args.error_log)
    app.run()


if __name__ == "__main__":
    main()
