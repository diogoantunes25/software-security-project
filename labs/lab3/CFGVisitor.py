import ast
from visitor import Visitor
import graphviz

vi = 0


class Vertex:

    def __init__(self):
        global vi
        self.vid = vi
        vi += 1


class Block(Vertex):

    def __init__(self, node):
        super().__init__()
        self.node = node

    def __repr__(self) -> str:
        return f"[{self.vid}] Block ({type(self.node).__name__})"


class Entry(Vertex):

    def __init__(self):
        super().__init__()

    def __repr__(self) -> str:
        return f"[{self.vid}] Entry"


class Exit(Vertex):

    def __init__(self):
        super().__init__()

    def __repr__(self) -> str:
        return f"[{self.vid}] Exit"


class Graph:

    def __init__(self):
        self.edges = {}

    def add(self, u, v):
        if u not in self.edges:
            self.edges[u] = []

        if v not in self.edges[u]:
            self.edges[u].append(v)

    def see(self):
        dot = graphviz.Digraph(comment='Directed Graph')

        for u in self.edges:
            for v in self.edges[u]:
                dot.edge(str(u), str(v))

        dot.render('graph', format='png', cleanup=True)
        dot.view()


class CFGVisitor(Visitor):
    """
    Generates a CFG for a given tree
    """

    def __init__(self):
        self.cfg = Graph()

    def see(self):
        self.cfg.see()

    def cfg(self, tree: ast.AST):
        self.visit(tree)
        self.simplify()
        self.see()

    def visit_multiple(self, nodes: list[ast.AST]):
        ventry = Entry()
        vexit = Exit()

        a = ventry
        for stmt in nodes:
            vin, vout = self.visit(stmt)
            self.cfg.add(a, vin)
            a = vout

        self.cfg.add(a, vexit)

        return (ventry, vexit)

    def visit_module(self, node: ast.Module):
        ventry = Entry()
        vexit = Exit()

        lentry, lexit = self.visit_multiple(node.body)
        self.cfg.add(ventry, lentry)
        self.cfg.add(lexit, vexit)

        self.cfg.see()

        return (ventry, vexit)

    def visit_assign(self, node: ast.Assign):
        ventry = Entry()
        me = Block(node)
        vexit = Exit()

        self.cfg.add(ventry, me)
        self.cfg.add(me, vexit)

        return (ventry, vexit)

    def visit_constant(self, node: ast.Constant):
        raise NotImplementedError()

    def visit_name(self, node: ast.Name):
        raise NotImplementedError()

    def visit_if(self, node: ast.If):
        ventry = Entry()
        vexit = Exit()

        vtest_in, vtest_out = self.visit(node.test)

        self.cfg.add(ventry, vtest_in)

        vbody_in, vbody_out = self.visit_multiple(node.body)
        self.cfg.add(vtest_out, vbody_in)
        self.cfg.add(vbody_out, vexit)

        if node.orelse:
            vorelse_in, vorelse_out = self.visit_multiple(node.orelse)
            self.cfg.add(vtest_out, vorelse_in)
            self.cfg.add(vorelse_out, vexit)
        else:
            self.cfg.add(ventry, vexit)

        return ventry, vexit

    def visit_compare(self, node: ast.Compare):
        ventry = Entry()
        me = Block(node)
        vexit = Exit()

        self.cfg.add(ventry, me)
        self.cfg.add(me, vexit)

        return ventry, vexit

    def visit_expr(self, node: ast.Expr):
        ventry = Entry()
        me = Block(node)
        vexit = Exit()

        self.cfg.add(ventry, me)
        self.cfg.add(me, vexit)

        return ventry, vexit

    def visit_call(self, node: ast.Call):
        raise NotImplementedError()

    def visit_while(self, node: ast.While):
        # FIXME: actually do stuff with orelse
        ventry = Entry()
        vexit = Exit()

        vtest_in, vtest_out = self.visit(node.test)

        self.cfg.add(ventry, vtest_in)
        self.cfg.add(vtest_out, vexit)

        vbody_in, vbody_out = self.visit_multiple(node.body)
        self.cfg.add(vtest_out, vbody_in)
        self.cfg.add(vbody_out, vtest_in)

        return ventry, vexit

    def visit(self, node: ast.AST):
        return self._visit(node)

    def _visit(self, node: ast.AST):
        if type(node) == ast.Module:
            return self.visit_module(node)

        elif type(node) == ast.Assign:
            return self.visit_assign(node)

        elif type(node) == ast.Constant:
            return self.visit_constant(node)

        elif type(node) == ast.Name:
            return self.visit_name(node)

        elif type(node) == ast.If:
            return self.visit_if(node)

        elif type(node) == ast.Compare:
            return self.visit_compare(node)

        elif type(node) == ast.Expr:
            return self.visit_expr(node)

        elif type(node) == ast.Call:
            return self.visit_call(node)

        elif type(node) == ast.While:
            return self.visit_while(node)
