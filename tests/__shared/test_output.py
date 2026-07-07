from unittest.mock import patch


from qost._shared.output import panel, table, tree_node, render_json, render_markdown


class TestPanel:
    def test_basic_panel(self):
        with patch("qost._shared.output.console.print") as mock:
            panel("Title", "Content")
            mock.assert_called_once()

    def test_panel_with_list(self):
        with patch("qost._shared.output.console.print") as mock:
            panel("Title", ["a", "b"])
            mock.assert_called_once()


class TestTable:
    def test_table_basic(self):
        with patch("qost._shared.output.console.print") as mock:
            table("Test", [("Name", "bold"), ("Value", "dim")], [["a", "1"], ["b", "2"]])
            mock.assert_called_once()

    def test_table_empty_rows(self):
        with patch("qost._shared.output.console.print") as mock:
            table("Test", [("Name", "bold"), ("Value", "dim")], [])
            mock.assert_called_once()


class TestTreeNode:
    def test_node_without_children(self):
        node = tree_node("root")
        assert node.label == "root"

    def test_node_with_children(self):
        node = tree_node("root", ["child1", "child2"])
        assert node.label == "root"
        children = list(node.children)
        assert len(children) == 2


class TestRenderJSON:
    def test_render_dict(self):
        result = render_json({"a": 1, "b": "hello"})
        assert '"a": 1' in result
        assert '"b": "hello"' in result

    def test_render_list(self):
        result = render_json([1, 2, 3])
        assert "1" in result

    def test_render_dataclass(self) -> None:
        from dataclasses import dataclass
        @dataclass
        class Foo:
            x: int
            y: str
        result = render_json(Foo(x=1, y="z"))
        assert '"x": 1' in result
        assert '"y": "z"' in result


class TestRenderMarkdown:
    def test_basic_markdown(self):
        with patch("qost._shared.output.console.print") as mock:
            render_markdown("# Hello")
            mock.assert_called_once()
