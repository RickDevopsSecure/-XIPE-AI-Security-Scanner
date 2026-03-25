"""
Logger estructurado para el framework de pentesting de IA.
"""
import logging
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green",
    "finding": "bold magenta",
})

console = Console(theme=custom_theme)


class PentestLogger:
    """Logger centralizado con soporte para consola y archivo."""
    
    def __init__(self, log_file: str, engagement_id: str):
        self.engagement_id = engagement_id
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Logger principal
        self.logger = logging.getLogger("inbest.pentest")
        self.logger.setLevel(logging.DEBUG)
        
        # Handler rico para consola
        rich_handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        rich_handler.setLevel(logging.DEBUG)
        
        # Handler para archivo (JSON estructurado)
        file_handler = logging.FileHandler(self.log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JsonFormatter(engagement_id))
        
        self.logger.addHandler(rich_handler)
        self.logger.addHandler(file_handler)
    
    def info(self, msg: str, **kwargs):
        self.logger.info(msg, extra={"extra_data": kwargs})
    
    def warning(self, msg: str, **kwargs):
        self.logger.warning(f"[yellow]{msg}[/yellow]", extra={"extra_data": kwargs})
    
    def error(self, msg: str, **kwargs):
        self.logger.error(f"[bold red]{msg}[/bold red]", extra={"extra_data": kwargs})
    
    def success(self, msg: str, **kwargs):
        self.logger.info(f"[bold green]✓ {msg}[/bold green]", extra={"extra_data": kwargs})
    
    def finding(self, severity: str, title: str, **kwargs):
        severity_colors = {
            "INFO": "cyan",
            "LOW": "blue",
            "MEDIUM": "yellow",
            "HIGH": "bold red",
            "CRITICAL": "bold white on red",
        }
        color = severity_colors.get(severity, "white")
        self.logger.warning(
            f"[{color}]🚨 [{severity}] {title}[/{color}]",
            extra={"extra_data": {"type": "FINDING", "severity": severity, **kwargs}}
        )
    
    def section(self, title: str):
        console.rule(f"[bold cyan]{title}[/bold cyan]")
    
    def module_start(self, module_name: str):
        console.print(f"\n[bold cyan]▶ Iniciando módulo:[/bold cyan] [white]{module_name}[/white]")
    
    def module_done(self, module_name: str, findings_count: int):
        console.print(
            f"[bold green]✓ Módulo completado:[/bold green] [white]{module_name}[/white] "
            f"— [magenta]{findings_count} hallazgo(s)[/magenta]\n"
        )


def get_logger(name: str) -> logging.Logger:
    """Return a standard Python logger prefixed with 'xipe.'"""
    return logging.getLogger(f"xipe.{name}")


class JsonFormatter(logging.Formatter):
    def __init__(self, engagement_id: str):
        super().__init__()
        self.engagement_id = engagement_id
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "engagement_id": self.engagement_id,
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
        }
        if hasattr(record, "extra_data") and record.extra_data:
            log_entry.update(record.extra_data)
        return json.dumps(log_entry, ensure_ascii=False)
