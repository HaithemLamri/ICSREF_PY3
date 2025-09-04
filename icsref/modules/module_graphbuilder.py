#!/usr/bin/env python3
# modules/module_graphbuilder.py

__author__ = "Tasos Keliris"

import os
import pygraphviz as pgv


def graphbuilder(self, args):
    """
    Create a visualization of the program call graph using Graphviz.

    No args

    Example:
        reversing@icsref:$ graphbuilder
    """
    # Clean up any previous artifacts first
    self.do_cleanup(None)

    try:
        prg = self.prg
    except AttributeError:
        print("Error: You need to first load or analyze a program")
        return 0

    # Ensure per-program results dir exists and dump per-function disassembly
    out_dir = os.path.join("results", prg.name)
    os.makedirs(out_dir, exist_ok=True)
    for fun in prg.Functions:
        fun_path = os.path.join(out_dir, f"{fun.name}.disasm")
        with open(fun_path, "w") as f:
            f.write("\n".join(fun.disasm))

    # Build callee classification sets once
    stat_names = set(prg.statlibs_dict.values()) if hasattr(prg, "statlibs_dict") else set()
    dyn_names  = set(prg.dynlibs_dict.values())  if hasattr(prg, "dynlibs_dict")  else set()

    # If everything is currently considered static, print a hint
    if stat_names and not dyn_names:
        print("[graphbuilder] Note: no dynamic library names detected; all edges may show as static (blue).")

    # Graph
    G = pgv.AGraph(strict=False, directed=True, ranksep="2")
    G.node_attr.update(shape="box", fontname="Helvetica")
    G.edge_attr.update(fontname="Helvetica")

    # Nodes for user-defined functions
    for fun in prg.Functions:
        G.add_node(fun.name, URL=f"{fun.name}.disasm", color="black")

    # Also add nodes for library names (so they’re boxes too)
    for name in stat_names | dyn_names:
        if not G.has_node(name):
            G.add_node(name, URL=f"{name}.disasm" if os.path.exists(os.path.join(out_dir, f"{name}.disasm")) else "",
                       color="black")

    # Edges with color mapping:
    #   static lib  -> blue
    #   dynamic lib -> red
    #   user func   -> gray
    red_count = blue_count = gray_count = 0

    for fun in prg.Functions:
        for callee_name, count in fun.calls.items():
            if callee_name in dyn_names:
                color, penwidth = "red", 2.0
                red_count += 1
            elif callee_name in stat_names:
                color, penwidth = "blue", 2.0
                blue_count += 1
            else:
                color, penwidth = "gray50", 1.2
                gray_count += 1

            # Ensure callee node exists
            if not G.has_node(callee_name):
                G.add_node(callee_name, color="black")

            G.add_edge(fun.name, callee_name, color=color, penwidth=str(penwidth), label=str(count))

    # Add a small legend subgraph
    lg = G.add_subgraph(name="cluster_legend", label="Legend", color="gray70", style="dashed")
    lg.add_node("static_lib (blue)", shape="box", color="black", fontcolor="blue")
    lg.add_node("dynamic_lib (red)", shape="box", color="black", fontcolor="red")
    lg.add_node("user_func (gray)", shape="box", color="black", fontcolor="gray50")
    lg.add_edge("static_lib (blue)", "dynamic_lib (red)", color="blue")
    lg.add_edge("dynamic_lib (red)", "user_func (gray)", color="red")

    # Layout and write SVG
    G.layout(prog="dot")
    out_svg = f"graph_{prg.name}.svg"
    G.draw(out_svg)

    # Move to results/<prg.name>/graph_<name>.svg
    final_path = os.path.join(out_dir, out_svg)
    if os.path.exists(final_path):
        os.remove(final_path)
    os.replace(out_svg, final_path)

    print(f"Generated {os.path.relpath(final_path)} "
          f"(edges: {blue_count} static/blue, {red_count} dynamic/red, {gray_count} user/gray)")
    return 0

