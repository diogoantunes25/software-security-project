import ast, sys, argparse, json
import IFVisitor as ifv
from flow_follow import *
import logging


def load_tree(filename: str) -> ast.AST:
    with open(filename, 'r') as fh:
        source = fh.read()
        return ast.parse(source)


def load_policy(filename: str) -> Policy:
    patterns = []
    with open(filename, 'r') as fh:
        content = json.load(fh)
        for el in content:
            patterns.append(Pattern.from_json(el))
            logging.info(f"Read pattern: {str(patterns[-1])}")

    return Policy(patterns)


def main(slice: str, patterns: str):
    tree = load_tree(slice)
    policy = load_policy(patterns)

    mtlb = MultiLabelling({})
    vulns = Vulnerability()

    vis = ifv.IFVisitor()
    ifresult = vis.visit(tree, policy, mtlb, vulns)

    print(vulns.to_json())


if __name__ == "__main__":
    # logging.basicConfig(level=logging.DEBUG)
    logging.basicConfig(level=logging.INFO, filename="log.log", filemode="w")

    parser = argparse.ArgumentParser(
        prog='py_analyser',
        description=
        'detects illegal information flows in python code slices based on provided vulnerability patterns'
    )

    parser.add_argument('slice')
    parser.add_argument('patterns')
    args = parser.parse_args()

    main(args.slice, args.patterns)
