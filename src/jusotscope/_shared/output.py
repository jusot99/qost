import json
from dataclasses import asdict, is_dataclass
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree
from rich import box

console = Console()


def panel(title: str, content: Any, border: str = "blue", width: int | None = None):
    console.print(Panel(content, title=title, border_style=border, box=box.ROUNDED, width=width))


def table(title: str, columns: list[tuple[str, str]], rows: list[list[str]]):
    t = Table(title=title, box=box.SIMPLE, title_justify="left")
    for col_name, col_style in columns:
        t.add_column(col_name, style=col_style)
    for row in rows:
        t.add_row(*row)
    console.print(t)


def tree_node(label: str, children: list[str] | None = None) -> Tree:
    t = Tree(label)
    if children:
        for c in children:
            t.add(c)
    return t


def render_json(data: Any) -> str:
    if is_dataclass(data):
        return json.dumps(asdict(data), indent=2, default=str)
    return json.dumps(data, indent=2, default=str)


def render_markdown(text: str):
    return console.print(Markdown(text))
