import ast
from flow_follow import *
import logging
import functools


class IFVisitor():

    def __init__(self):
        # Context multilabel used for conditionals
        self.contexts = [MultiLabel({})]

    def current_context(self):
        return self.contexts[-1].clone()

    def flat_vars(node: ast.AST) -> list[str]:
        """
        Receives either a name or an attribute and returns the list 
        of names.
        Examples:
            - flat_vars(a) = ['a']
            - flat_vars(a.b.c) = ['a', 'b', 'c']
        """

        assert (type(node) == ast.Name or type(node) == ast.Attribute)
        if type(node) == ast.Name: return [node.id]
        return IFVisitor.flat_vars(node.value) + [node.attr]

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

        elif type(node) == ast.BinOp:
            return self.visit_bin_op(node, policy, mtlb, vulns)

        elif type(node) == ast.Attribute:
            return self.visit_attribute(node, policy, mtlb, vulns)

        else:
            raise ValueError(
                f"Unknown (or Unsupported) AST node - {type(node)}")

    def visit_multiple(self, nodes: list[ast.AST], policy: Policy,
                       mtlb: MultiLabelling,
                       vulns: Vulnerability) -> MultiLabelling:

        for stmt in nodes:
            value = self.visit(stmt, policy, mtlb, vulns)
            if type(value) == MultiLabelling:
                mtlb = value

        return mtlb

    def visit_module(self, node: ast.Module, policy: Policy,
                     mtlb: MultiLabelling,
                     vulns: Vulnerability) -> MultiLabelling:
        return self.visit_multiple(node.body, policy, mtlb, vulns)

    def visit_assign(self, node: ast.Assign, policy: Policy,
                     mtlb: MultiLabelling,
                     vulns: Vulnerability) -> MultiLabelling:

        value_mlb = self.visit(node.value, policy, mtlb, vulns)
        new = mtlb.clone()

        targets = []
        for target in node.targets:
            targets += IFVisitor.flat_vars(target)

        for target in targets:
            logging.debug(
                f"checking if the multilabel {value_mlb} is illegal for {target}"
            )
            bad_labels = policy.find_illegal(target, value_mlb)
            logging.debug(
                f"Saving the following vulnerabilities for {target} - {bad_labels}"
            )
            vulns.save(Element(target, node.lineno), bad_labels)

            new.mlabel_set(target, value_mlb)

        logging.debug(f"Multilabelling after assign is {str(new)}")

        return new

    def visit_constant(self, node: ast.Constant, policy: Policy,
                       mtlb: MultiLabelling,
                       vulns: Vulnerability) -> MultiLabel:
        return self.current_context()

    def visit_name(self, node: ast.Name, policy: Policy, mtlb: MultiLabelling,
                   vulns: Vulnerability) -> MultiLabel:

        mlb = mtlb.mlabel_of(node.id)

        if mlb is not None:
            # Some variables might have markes as unitilialized. The line number
            # should be replaced in (the vulnerability is only reported on evaluation)
            for lbl in mlb.labels.values():
                for val in lbl.values:
                    if val.lineno == -1:
                        val.lineno = node.lineno

            # if variable is a source for some pattern, it's always a source
            # so, the multilabel with this information must be merged with remaining information
            src_patterns = policy.search_source(node.id)
            og_mlb = MultiLabel({})
            for pat in src_patterns:
                og_mlb.labels[pat] = Label(pat,
                                           set([Source(node.id, node.lineno)]))
            mlb = mlb.combine(og_mlb)

            logging.debug(
                f"Evaluated {node.id} to {mlb} (before combining with context)"
            )

            return mlb.combine(self.current_context())

        # if variable does not have multilabel (i.e. it's not initialized), it's a source for all patterns
        mlb = MultiLabel({})
        for pattern in policy.patterns:
            # Create label with single source and no sanitizers
            mlb.labels[pattern.name] = Label(
                pattern.name, set([Source(node.id, node.lineno)]))

        logging.debug(
            f"not initialized variable found '{node.id}'. the multilabel is {mlb}"
        )

        return mlb.combine(self.current_context())

    def visit_if(self, node: ast.If, policy: Policy, mtlb: MultiLabelling,
                 vulns: Vulnerability) -> MultiLabelling:

        condmlb = self.visit(node.test, policy, mtlb, vulns)

        logging.debug(f"pushing the following context: {condmlb}")
        self.contexts.append(condmlb.clone().filter_implicit(policy))

        taken = self.visit_multiple(node.body, policy, mtlb, vulns)
        not_taken = mtlb
        if node.orelse:
            logging.debug("visiting orelse node")
            not_taken = self.visit_multiple(node.orelse, policy, mtlb, vulns)

        self.contexts.pop()

        #all variables defined in multilabelling from one branch and not the other
        # should be added to the branches multilabelling with the initial value (as if evaluated
        # at start)

        for (a, b) in ((taken, not_taken), (not_taken, taken)):
            for var in a.mapping:
                if var not in b.mapping:
                    lbl = MultiLabel({})
                    for pattern in policy.patterns:
                        lbl.labels[pattern.name] = Label(
                            pattern.name, set([Source(var, -1)]))
                    b.mapping[var] = lbl

        ans = taken.combine(not_taken)

        logging.debug(f"taken path: {taken}")
        logging.debug(f"not taken path: {not_taken}")
        logging.debug(f"taken + not taken path: {ans}")

        return ans

    def visit_compare(self, node: ast.Compare, policy: Policy,
                      mtlb: MultiLabelling,
                      vulns: Vulnerability) -> MultiLabel:

        aggregate: MultiLabel = self.visit(node.left, policy, mtlb, vulns)

        for val in node.comparators:
            aggregate = self.visit(val, policy, mtlb, vulns).combine(aggregate)

        return aggregate

    def visit_expr(self, node: ast.Expr, policy: Policy, mtlb: MultiLabelling,
                   vulns: Vulnerability) -> MultiLabel:
        return self.visit(node.value, policy, mtlb, vulns)

    def visit_call(self, node: ast.Call, policy: Policy, mtlb: MultiLabelling,
                   vulns: Vulnerability) -> MultiLabel:
        vars = IFVisitor.flat_vars(node.func)
        name = vars[-1]

        if len(vars) > 1:
            # Turn a.b.c() into a + b + c()
            fake_nodes = list(
                map(lambda n: ast.Name(n, None, lineno=node.lineno),
                    vars[:-1]))
            fake_nodes.append(
                ast.Call(ast.Name(name, lineno=node.lineno),
                         node.args,
                         node.keywords,
                         lineno=node.lineno))
            fake_sum = functools.reduce(
                lambda a, b: ast.BinOp(
                    left=a, op=ast.Add(), right=b, lineno=node.lineno),
                fake_nodes)
            logging.debug(
                f"Reduced {ast.dump(node)} into {ast.dump(fake_sum)}")
            return self.visit(fake_sum, policy, mtlb, vulns)

        # Merge all multilabels of the arguments
        mlb = self.current_context()
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
            lbl.add_source(Source(name, node.lineno))

        # Patterns for which name is a sanitizer - is combination of label of args + sanitization
        sanitizers = policy.search_sanitizer(name)
        sanitizers = list(
            map(lambda n: policy.get_vulnerability(n), sanitizers))
        for pattern in sanitizers:
            logging.debug(f"{name} is a sanitizer for {str(pattern)}")
            lbl = mlb.get_label(pattern.name)
            lbl.add_sanitizer(Element(name, node.lineno))

        # Patterns for which name is a sink - check is there's any violation
        bad_labels = policy.find_illegal(name, mlb)
        logging.debug(
            f"Saving the following vulnerabilities for {name} - {bad_labels}")
        vulns.save(Element(name, node.lineno), bad_labels)

        logging.debug(f"Call for {name} has final multilabel of {str(mlb)}")

        return mlb

    def visit_while(self, node: ast.While, policy: Policy,
                    mtlb: MultiLabelling,
                    vulns: Vulnerability) -> MultiLabelling:

        condmlb = self.visit(node.test, policy, mtlb, vulns)
        self.contexts.append(condmlb.clone().filter_implicit(policy))

        aggregate_cond_mlb = condmlb
        old_mtlb = None
        i = 0
        logging.debug(f"(start) Multilabelling is {mtlb}")
        # Uses fixed point algorithm
        # TODO: do the same as in the if case (regarding unitialized variables)
        while old_mtlb != mtlb:
            old_mtlb = mtlb.clone()

            taken = self.visit_multiple(node.body, policy, mtlb, vulns)
            not_taken = mtlb
            # TODO: handle orelse (a bit akward in while context)

            mtlb = taken.combine(not_taken)
            logging.debug(f"(i={i}) Multilabelling is {mtlb}")

            condmlb = self.visit(node.test, policy, mtlb, vulns)
            aggregate_cond_mlb = aggregate_cond_mlb.combine(condmlb)
            i += 1
            self.contexts.append(condmlb.clone())

        logging.debug(f"parsing while stopped after {i} iterations")
        for _ in range(i + 1):
            self.contexts.pop()

        # leave as context the aggregate multilabel (encodes all possible values
        # that were in the condition)
        self.contexts.append(aggregate_cond_mlb)

        return mtlb

    def visit_bin_op(self, node: ast.BinOp, policy: Policy,
                     mtlb: MultiLabelling, vulns: Vulnerability) -> MultiLabel:

        left = self.visit(node.left, policy, mtlb, vulns)
        logging.info(f"left of binary node: {str(left)}")
        right = self.visit(node.right, policy, mtlb, vulns)
        logging.info(f"right of binary node: {str(right)}")

        return left.combine(right)

    def visit_attribute(self, node: ast.Attribute, policy: Policy,
                        mtlb: MultiLabelling,
                        vulns: Vulnerability) -> MultiLabel:

        # Note that this method is only called when attribute is on the right
        # hand side (so this is to be handled as a binary operation)

        value_lbl = self.visit(node.value, policy, mtlb, vulns)
        logging.info(f"value of attribute node: {str(value_lbl)}")

        # I want to handle the attribute as variable, so instead of copying code,
        # create a fake Name node
        fake_node = ast.Name(node.attr, None)
        attr_lbl = self.visit(fake_node, policy, mtlb, vulns)
        logging.info(f"attr of attribute node: {str(attr_lbl)}")

        return value_lbl.combine(attr_lbl)
