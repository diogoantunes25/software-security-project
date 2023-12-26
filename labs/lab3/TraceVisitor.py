import ast

WHILE_COUNT = 50


class TraceVisitor():

    def __init__(self):
        pass

    def visit(self, node: ast.AST, paths: list[str]) -> list[str]:
        if type(node) == ast.Module:
            return self.visit_module(node, paths)

        elif type(node) == ast.Assign:
            return self.visit_assign(node, paths)

        elif type(node) == ast.Constant:
            return self.visit_constant(node, paths)

        elif type(node) == ast.Name:
            return self.visit_name(node, paths)

        elif type(node) == ast.If:
            return self.visit_if(node, paths)

        elif type(node) == ast.Compare:
            return self.visit_compare(node, paths)

        elif type(node) == ast.Expr:
            return self.visit_expr(node, paths)

        elif type(node) == ast.Call:
            return self.visit_call(node, paths)

        elif type(node) == ast.While:
            return self.visit_while(node, paths)

        else:
            raise ValueError(
                f"Unknown (or Unsupported) AST node - {type(node)}")

    def visit_multiple(self, nodes: list[ast.AST],
                       paths: list[str]) -> list[str]:
        for stmt in nodes:
            paths = self.visit(stmt, paths)
        return paths

    def visit_module(self, node: ast.Module, paths: list[str]) -> list[str]:
        return self.visit_multiple(node.body, paths)

    def visit_assign(self, node: ast.Assign, paths: list[str]) -> list[str]:
        return [p + [node] for p in paths]

    def visit_constant(self, node: ast.Constant,
                       paths: list[str]) -> list[str]:
        return paths

    def visit_name(self, node: ast.Name, paths: list[str]) -> list[str]:
        return paths

    def visit_if(self, node: ast.If, paths: list[str]) -> list[str]:
        paths = self.visit(node.test, paths)

        left = self.visit_multiple(node.body, paths)

        if node.orelse:
            right = self.visit_multiple(node.orelse, paths)
            return left + right
        else:
            return left + paths

    def visit_compare(self, node: ast.Compare, paths: list[str]) -> list[str]:
        return [p + [node] for p in paths]

    def visit_expr(self, node: ast.Expr, paths: list[str]) -> list[str]:
        return paths

    def visit_call(self, node: ast.Call, paths: list[str]) -> list[str]:
        return [p + [node] for p in paths]

    def visit_while(self, node: ast.While, paths: list[str]) -> list[str]:

        total = []
        paths = self.visit(node.test, paths)

        total += paths

        for _ in range(WHILE_COUNT):
            paths = self.visit_multiple(node.body, paths)
            paths = self.visit(node.test, paths)
            total += paths

        return total
