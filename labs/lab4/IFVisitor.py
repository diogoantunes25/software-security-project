import ast
from flow_follow import *
import logging

WHILE_COUNT = 50


class IFVisitor():

    def __init__(self):
        pass

    def visit(self, node: ast.AST, policy: Policy, mtlb: MultiLabelling,
              vulns: Vulnerability):
        if type(node) == ast.Module:
            return self.visit_module(node, policy, mtlb, vulns)

        elif type(node) == ast.Assign:
            return self.visit_assign(node, policy, mtlb, vulns)

        elif type(node) == ast.Constant:
            return self.visit_constant(node, policy, mtlb, vulns)

        elif type(node) == ast.Name:
            return self.visit_name(node, policy, mtlb, vulns)

        elif type(node) == ast.If:
            return self.visit_if(node, policy, mtlb, vulns)

        elif type(node) == ast.Compare:
            return self.visit_compare(node, policy, mtlb, vulns)

        elif type(node) == ast.Expr:
            return self.visit_expr(node, policy, mtlb, vulns)

        elif type(node) == ast.Call:
            return self.visit_call(node, policy, mtlb, vulns)

        elif type(node) == ast.While:
            return self.visit_while(node, policy, mtlb, vulns)

        else:
            raise ValueError(
                f"Unknown (or Unsupported) AST node - {type(node)}")

    def visit_multiple(self, nodes: list[ast.AST], policy: Policy,
                       mtlb: MultiLabelling,
                       vulns: Vulnerability) -> MultiLabelling:

        for stmt in nodes:
            mtlb = self.visit(stmt, policy, mtlb, vulns)

        return mtlb

    def visit_module(self, node: ast.Module, policy: Policy,
                     mtlb: MultiLabelling,
                     vulns: Vulnerability) -> MultiLabelling:
        return self.visit_multiple(node.body, policy, mtlb, vulns)

    def visit_assign(self, node: ast.Assign, policy: Policy,
                     mtlb: MultiLabelling,
                     vulns: Vulnerability) -> MultiLabelling:
        mlb = self.visit(node.value, policy, mtlb, vulns)
        new = mtlb.clone()

        for target in node.targets:
            new.mlabel_set(target.id, mlb)

        logging.debug(f"Multilabelling after assign is {str(new)}")

        return new

    def visit_constant(self, node: ast.Constant, policy: Policy,
                       mtlb: MultiLabelling,
                       vulns: Vulnerability) -> MultiLabel:
        return MultiLabel()

    def visit_name(self, node: ast.Name, policy: Policy, mtlb: MultiLabelling,
                   vulns: Vulnerability) -> MultiLabel:
        return mtlb.mlabel_of(node.id)

    def visit_if(self, node: ast.If, policy: Policy, mtlb: MultiLabelling,
                 vulns: Vulnerability) -> MultiLabelling:

        self.visit_multiple(node.body, policy, mtlb, vulns)

        if node.orelse:
            self.visit_multiple(node.orelse, policy, mtlb, vulns)

    def visit_compare(self, node: ast.Compare, policy: Policy,
                      mtlb: MultiLabelling,
                      vulns: Vulnerability) -> MultiLabel:
        return MultiLabel()

    def visit_expr(self, node: ast.Expr, policy: Policy, mtlb: MultiLabelling,
                   vulns: Vulnerability) -> MultiLabel:
        return self.visit(node.value, policy, mtlb, vulns)

    def visit_call(self, node: ast.Call, policy: Policy, mtlb: MultiLabelling,
                   vulns: Vulnerability) -> MultiLabel:
        name = node.func.id

        # Merge all multilabels of the arguments
        mlb = MultiLabel({})
        for arg in node.args:
            argmlb = self.visit(arg, policy, mtlb, vulns)
            logging.debug(
                f"Argument for {name} has the following multilabel: {str(argmlb)}"
            )
            mlb = mlb.combine(argmlb)

        logging.debug(f"Call for {name} has initial multilabel of {str(mlb)}")

        # Patterns for which name is a source - add new source to that label
        sources = policy.search_source(name)
        sources = list(map(lambda n: policy.get_vulnerability(n), sources))
        for pattern in sources:
            logging.debug(f"{name} is a source for {str(pattern)}")
            lbl = mlb.get_label(pattern.name)
            lbl.add_source(name)

        # Patterns for which name is a sanitizer - is combination of label of args + sanitization
        sanitizers = policy.search_sanitizer(name)
        sanitizers = list(
            map(lambda n: policy.get_vulnerability(n), sanitizers))
        for pattern in sanitizers:
            logging.debug(f"{name} is a sanitizer for {str(pattern)}")
            lbl = mlb.get_label(pattern.name)
            lbl.add_sanitizer(name)

        # Patterns for which name is a sink - check is there's any violation
        bad_labels = policy.find_illegal(name, mlb)
        logging.debug(
            f"Saving the following vulnerabilities for {name} - {bad_labels}")
        vulns.save(name, bad_labels)

        logging.debug(f"Call for {name} has final multilabel of {str(mlb)}")
        return mlb

    def visit_while(self, node: ast.While, policy: Policy,
                    mtlb: MultiLabelling,
                    vulns: Vulnerability) -> MultiLabelling:

        self.visit(node.test, policy, mtlb, vulns)

        for _ in range(WHILE_COUNT):
            self.visit(node.body, policy, mtlb, vulns)
            self.visit(node.test, policy, mtlb, vulns)
