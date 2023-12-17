import ast
from visitor import Visitor


class PrintVisitor(Visitor):

    def __init__(self):
        pass

    def pre(self, node: ast.AST):
        if hasattr(node, 'lineno'):
            print(f"{type(node).__name__} @ {node.lineno}")
        else:
            print(f"{type(node).__name__}")

    def visit_module(self, node: ast.Module):
        for stmt in node.body:
            self.visit(stmt)

    def visit_assign(self, node: ast.Assign):
        self.visit(node.value)
        for target in node.targets:
            self.visit(target)

    def visit_constant(self, node: ast.Constant):
        pass

    def visit_name(self, node: ast.Name):
        pass

    def visit_if(self, node: ast.If):
        self.visit(node.test)

        for stmt in node.body:
            self.visit(stmt)

        for stmt in node.orelse:
            self.visit(stmt)

    def visit_compare(self, node: ast.Compare):
        self.visit(node.left)
        for comp in node.comparators:
            self.visit(comp)

    def visit_expr(self, node: ast.Expr):
        self.visit(node.value)

    def visit_call(self, node: ast.Call):
        for arg in node.args:
            self.visit(arg)

        for kw in node.keywords:
            self.visit(kw.value)

    def visit_while(self, node: ast.While):
        self.visit(node.test)

        for stmt in node.body:
            self.visit(stmt)

        for stmt in node.orelse:
            self.visit(stmt)
