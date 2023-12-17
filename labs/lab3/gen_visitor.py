import argparse


def gen(filename: str, visitor: str):
    with open(filename, 'r') as fh:
        nodes = map(lambda x: x.strip(), fh.readlines())

        with open(f"{visitor}.py", 'w') as wfh:
            wfh.write(f"import ast\n")
            wfh.write(f"from visitor import Visitor\n\n")
            wfh.write(f"class {visitor}(Visitor):\n\n")

            wfh.write(f"    def __init__(self):\n")
            wfh.write(f"        raise NotImplementedError()\n\n")

            for node in nodes:
                wfh.write(
                    f"    def visit_{node.lower()}(self, node: ast.{node}):\n")
                wfh.write(f"        raise NotImplementedError()\n\n")


def gen_abstract(filename: str):
    with open(filename, 'r') as fh:
        nodes = list(map(lambda x: x.strip(), fh.readlines()))
        with open(f"visitor.py", 'w') as wfh:

            wfh.write(f"import ast\n\n")

            wfh.write(f"class Visitor:\n\n")

            wfh.write(f"    def __init__(self):\n")
            wfh.write(f"        raise NotImplementedError()\n\n")

            wfh.write(f"    def pre(self, node: ast.AST):\n")
            wfh.write(f"        pass\n\n")

            wfh.write(f"    def post(self, node: ast.AST):\n")
            wfh.write(f"        pass\n\n")

            wfh.write(f"    def visit(self, node: ast.AST):\n")
            wfh.write(f"        self.pre(node)\n")
            wfh.write(f"        self._visit(node)\n")
            wfh.write(f"        self.post(node)\n\n")

            wfh.write(f"    def _visit(self, node: ast.AST):\n")
            wfh.write(f"        if type(node) == ast.{nodes[0]}:\n")
            wfh.write(f"            self.visit_{nodes[0].lower()}(node)\n\n")

            for node in nodes[1:]:
                wfh.write(f"        elif type(node) == ast.{node}:\n")
                wfh.write(f"            self.visit_{node.lower()}(node)\n\n")

            wfh.write(f"        else:\n")
            wfh.write(
                "            raise ValueError(f\"Unknown (or Unsupported) AST node - {type(node)}\")\n"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='gen_visitor',
                                     description='generates visitor')
    parser.add_argument('filename')
    parser.add_argument('-v', '--visitor_name')
    parser.add_argument('-a', '--abstract', action='store_true')

    args = parser.parse_args()

    if args.abstract:
        gen_abstract(args.filename)
    else:
        gen(args.filename, args.visitor_name)
