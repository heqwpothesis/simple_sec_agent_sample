#!/usr/bin/env python3
"""
IDOR Vulnerability Detection Agent Demo

This script demonstrates automated detection of Insecure Direct Object Reference (IDOR) 
vulnerabilities using AI agents. It runs vulnerable Flask applications and tests them
with different detection strategies.

Usage:
    python demo.py --app [1|2] --agent [simple|openapi|all]
    
Educational Purpose Only - For defensive security research and training.
"""

import os
import sys
import time
import signal
import argparse
import subprocess
import threading
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

console = Console()

class VulnAppRunner:
    """Manages vulnerable Flask application lifecycle"""
    
    def __init__(self, app_script: str, port: int = 5005):
        self.app_script = app_script
        self.port = port
        self.process = None
        
    def start(self):
        """Start the vulnerable application"""
        console.print(f"[yellow]Starting {self.app_script} on port {self.port}...[/]")
        self.process = subprocess.Popen([
            sys.executable, self.app_script
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(2)  # Give app time to start
        
    def stop(self):
        """Stop the vulnerable application"""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            console.print(f"[red]Stopped {self.app_script}[/]")

def run_agent(agent_type: str, base_url: str = "http://127.0.0.1:5005"):
    """Run the specified IDOR detection agent"""
    
    agent_map = {
        "simple": "agent/simple_agent.py",
        "openapi": "agent/openapi_agent.py",
        "enhanced": "agent/enhanced_agent.py"
    }
    
    if agent_type not in agent_map:
        console.print(f"[red]Unknown agent type: {agent_type}[/]")
        return False
        
    agent_script = agent_map[agent_type]
    console.print(f"\n[cyan]Running {agent_type} agent ({agent_script})...[/]")
    
    try:
        result = subprocess.run([
            sys.executable, agent_script, 
            "--base-url", base_url,
            "--username", "bob",
            "--password", "bob123"
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            console.print(f"[green]✓ {agent_type} agent completed successfully[/]")
            return True
        else:
            console.print(f"[red]✗ {agent_type} agent failed[/]")
            console.print(f"Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        console.print(f"[red]✗ {agent_type} agent timed out[/]")
        return False
    except Exception as e:
        console.print(f"[red]✗ {agent_type} agent error: {e}[/]")
        return False

def show_banner():
    """Display demo banner"""
    banner = """
    # IDOR Vulnerability Detection Agent Demo
    
    **Educational Purpose Only** - Demonstrates automated detection of 
    Insecure Direct Object Reference vulnerabilities using AI agents.
    
    ## Available Components:
    - **vulnerable_app/basic_app.py**: Basic IDOR vulnerable Flask app
    - **vulnerable_app/advanced_app.py**: Enhanced app with OpenAPI support  
    - **agent/simple_agent.py**: Simple rule-based IDOR detection
    - **agent/openapi_agent.py**: OpenAPI-driven detection
    - **agent/enhanced_agent.py**: Advanced multi-step detection
    """
    console.print(Panel(Markdown(banner), title="IDOR Demo", border_style="blue"))

def show_results():
    """Show results summary"""
    report_files = [
        ("idor_report.md", "IDOR Report"),
        ("enhanced_idor_report.md", "Enhanced IDOR Report")
    ]
    
    for report_file, title in report_files:
        report_path = Path(report_file)
        if report_path.exists():
            console.print(f"\n[green]📋 {title} Generated:[/]")
            with open(report_path, 'r', encoding='utf-8') as f:
                content = f.read()
            console.print(Panel(Markdown(content[:2000] + "..." if len(content) > 2000 else content), 
                               title=title, border_style="green"))
            break

def main():
    parser = argparse.ArgumentParser(description="IDOR Detection Agent Demo")
    parser.add_argument("--app", choices=["1", "2"], default="2", 
                       help="Vulnerable app to run (1=basic, 2=enhanced)")
    parser.add_argument("--agent", choices=["simple", "openapi", "enhanced", "all"], default="enhanced",
                       help="Detection agent to run")
    parser.add_argument("--port", type=int, default=5005, help="Port for vulnerable app")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner display")
    
    args = parser.parse_args()
    
    if not args.no_banner:
        show_banner()
    
    # Select vulnerable app
    app_map = {
        "1": "vulnerable_app/basic_app.py",
        "2": "vulnerable_app/advanced_app.py"
    }
    app_script = app_map[args.app]
    if not Path(app_script).exists():
        console.print(f"[red]Error: {app_script} not found[/]")
        return 1
        
    # Start vulnerable application
    app_runner = VulnAppRunner(app_script, args.port)
    
    def signal_handler(sig, frame):
        console.print("\n[yellow]Shutting down...[/]")
        app_runner.stop()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        app_runner.start()
        base_url = f"http://127.0.0.1:{args.port}"
        
        # Run detection agents
        if args.agent == "all":
            agents = ["simple", "openapi", "enhanced"]
        else:
            agents = [args.agent]
            
        results = []
        for agent in agents:
            success = run_agent(agent, base_url)
            results.append((agent, success))
            
        # Show summary
        console.print("\n[bold]Detection Summary:[/]")
        table = Table()
        table.add_column("Agent", style="cyan")
        table.add_column("Status", style="green")
        
        for agent, success in results:
            status = "✓ Success" if success else "✗ Failed"
            table.add_row(agent, status)
            
        console.print(table)
        show_results()
        
    finally:
        app_runner.stop()
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
