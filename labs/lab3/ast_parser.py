import ast, sys, argparse
import PrintVisitor as pv
import CFGVisitor as cfgv


def ast_parse(filename: str):
    with open(filename, 'r') as fh:
        source = fh.read()
        tree = ast.parse(source)
        print(ast.dump(tree, indent=4))

        vis = cfgv.CFGVisitor()
        vis.visit(tree)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='ast_parser', description='parses python AST as does stuff')
    parser.add_argument('filename')

    args = parser.parse_args()

    ast_parse(args.filename)
