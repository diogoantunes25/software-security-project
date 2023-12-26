import ast, sys, argparse
import PrintVisitor as pv
import CFGVisitor as cfgv
import TraceVisitor as tv


def ast_parse(filename: str):
    with open(filename, 'r') as fh:
        source = fh.read()
        tree = ast.parse(source)
        print(ast.dump(tree, indent=4))

        # vis = cfgv.CFGVisitor()
        vis = tv.TraceVisitor()
        paths = vis.visit(tree, [[]])
        print(f"found {len(paths)} paths")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='ast_parser', description='parses python AST as does stuff')
    parser.add_argument('filename')

    args = parser.parse_args()

    ast_parse(args.filename)
