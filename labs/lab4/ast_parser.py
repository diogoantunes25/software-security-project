import ast, sys, argparse
import IFVisitor as ifv
from flow_follow import *


def ast_parse(filename: str):
    with open(filename, 'r') as fh:
        source = fh.read()
        tree = ast.parse(source)
        print(ast.dump(tree, indent=4))

        pattern = Pattern("dsa_pat", ["s1", "s2"], ["san"], ["b1", "b2", "b3"],
                          False)
        policy = Policy([pattern])
        mtlb = MultiLabelling({})
        vulns = Vulnerability()

        vis = ifv.IFVisitor()
        ifresult = vis.visit(tree, policy, mtlb, vulns)
        print(ifresult)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='ast_parser', description='parses python AST as does stuff')
    parser.add_argument('filename')

    args = parser.parse_args()

    ast_parse(args.filename)
