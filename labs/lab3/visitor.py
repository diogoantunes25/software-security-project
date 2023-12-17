import ast


class Visitor:

    def __init__(self):
        raise NotImplementedError()

    def pre(self, node: ast.AST):
        pass

    def post(self, node: ast.AST):
        pass

    def visit(self, node: ast.AST):
        self.pre(node)
        self._visit(node)
        self.post(node)

    def _visit(self, node: ast.AST):
        if type(node) == ast.Module:
            self.visit_module(node)

        elif type(node) == ast.Assign:
            self.visit_assign(node)

        elif type(node) == ast.Constant:
            self.visit_constant(node)

        elif type(node) == ast.Name:
            self.visit_name(node)

        elif type(node) == ast.If:
            self.visit_if(node)

        elif type(node) == ast.Compare:
            self.visit_compare(node)

        elif type(node) == ast.Expr:
            self.visit_expr(node)

        elif type(node) == ast.Call:
            self.visit_call(node)

        elif type(node) == ast.While:
            self.visit_while(node)

        else:
            raise ValueError(
                f"Unknown (or Unsupported) AST node - {type(node)}")
