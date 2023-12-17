import ast
from visitor import Visitor


class TraceVisitor(Visitor):

    def __init__(self):
        raise NotImplementedError()

    def visit_module(self, node: ast.Module):
        raise NotImplementedError()

    def visit_assign(self, node: ast.Assign):
        raise NotImplementedError()

    def visit_constant(self, node: ast.Constant):
        raise NotImplementedError()

    def visit_name(self, node: ast.Name):
        raise NotImplementedError()

    def visit_if(self, node: ast.If):
        raise NotImplementedError()

    def visit_compare(self, node: ast.Compare):
        raise NotImplementedError()

    def visit_expr(self, node: ast.Expr):
        raise NotImplementedError()

    def visit_call(self, node: ast.Call):
        raise NotImplementedError()

    def visit_while(self, node: ast.While):
        raise NotImplementedError()
