#!/usr/bin/env python3
import io
import re
import pandas as pd
import plotly.graph_objects as go
from pathlib import Path

# Curated palette for premium aesthetics
COLORS = {
    "blue": {
        "node": "#4A6FA5",          # Steel blue
        "link": "rgba(74, 111, 165, 0.25)"
    },
    "green": {
        "node": "#2D9E6B",         # Forest green
        "link": "rgba(45, 158, 107, 0.35)"
    },
    "red": {
        "node": "#C0392B",           # Coral red
        "link": "rgba(192, 57, 43, 0.30)"
    },
    "grey": {
        "node": "#4A4A4A",          # Charcoal gray for intermediate levels
        "link": "rgba(74, 74, 74, 0.25)"
    }
}

DEFAULT_COLOR = "blue"

def parse_sankey_csv(csv_content_or_path) -> pd.DataFrame:
    """
    Parses Sankey CSV data. Handles trailing comments like '--> green color'
    and extracts node names, link values, and color directives.
    """
    if isinstance(csv_content_or_path, Path) or (isinstance(csv_content_or_path, str) and '\n' not in csv_content_or_path):
        with open(csv_content_or_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    else:
        lines = csv_content_or_path.strip().split('\n')

    rows = []
    # Skip header
    header = lines[0]
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        
        # Split into elements (Source, Dest, Value/Comment)
        parts = line.split(',')
        if len(parts) < 3:
            continue
            
        source = parts[0].strip()
        dest = parts[1].strip()
        
        # Handle trailing comments (e.g. 54        --> green color)
        val_and_comment = parts[2]
        color_directive = None
        
        if '-->' in val_and_comment:
            val_part, comment_part = val_and_comment.split('-->', 1)
            value = float(val_part.strip())
            comment = comment_part.lower()
            if 'green' in comment:
                color_directive = 'green'
            elif 'red' in comment:
                color_directive = 'red'
            elif 'blue' in comment:
                color_directive = 'blue'
            elif 'grey' in comment or 'gray' in comment:
                color_directive = 'grey'
        else:
            value = float(val_and_comment.strip())
            
        rows.append({
            'source': source,
            'dest': dest,
            'value': value,
            'color_directive': color_directive
        })
        
    return pd.DataFrame(rows)

def create_sankey_diagram(df: pd.DataFrame, title: str = "Sankey Flow Diagram", filename_stem: str = "") -> go.Figure:
    """
    Builds a beautifully styled Plotly Sankey diagram from the parsed DataFrame.
    """
    # 1. Identify all unique nodes
    unique_nodes = list(pd.concat([df['source'], df['dest']]).unique())
    node_to_idx = {node: i for i, node in enumerate(unique_nodes)}
    
    # 2. Assign node colors
    node_colors = []
    node_color_map = {}
    
    for node in unique_nodes:
        # Determine color for the node
        matched_rows = df[df['dest'] == node]
        color_key = None
        if not matched_rows.empty:
            color_key = matched_rows.iloc[0]['color_directive']
            
        if not color_key:
            # Fallback based on text content
            if "cfr" in node.lower() or "fixed" in node.lower() or "success" in node.lower():
                color_key = "green"
            elif "escalat" in node.lower() or "fail" in node.lower() or "error" in node.lower():
                color_key = "red"
            elif node in ("L0", "L1", "L2"):
                color_key = "grey"
            else:
                color_key = DEFAULT_COLOR
                
        node_color_map[node] = color_key
        node_colors.append(COLORS[color_key]["node"])
        
    # 3. Build links (sources, targets, values, colors)
    sources = []
    targets = []
    values = []
    link_colors = []
    
    for _, row in df.iterrows():
        s_idx = node_to_idx[row['source']]
        t_idx = node_to_idx[row['dest']]
        val = row['value']
        
        sources.append(s_idx)
        targets.append(t_idx)
        values.append(val)
        
        # Color the link based on link directive or destination node color
        color_key = row['color_directive'] or node_color_map[row['dest']]
        link_colors.append(COLORS[color_key]["link"])
        
    # 4. Polish labels
    polished_labels = []
    for node in unique_nodes:
        # Check if the node label already has a numeric suffix like ": 54" or "— 54"
        if re.search(r'[:—]\s*\d+', node):
            polished_labels.append(node)
        else:
            in_flow = df[df['dest'] == node]['value'].sum()
            out_flow = df[df['source'] == node]['value'].sum()
            flow = max(in_flow, out_flow)
            
            # Append flow value to leaf nodes (destinations with no outgoing flow)
            if in_flow > 0 and out_flow == 0:
                polished_labels.append(f"{node}: {int(flow)}")
            else:
                polished_labels.append(node)
                
    # 5. Position nodes and add annotations
    node_x = None
    node_y = None
    annotations = []
    width = 800
    height = 400
    
    # Match L0 + L1 Cascade
    if (filename_stem == "sankey_l0_l1" or len(unique_nodes) == 6) and any("escalated to l1" in n.lower() for n in unique_nodes):
        x_map = {
            "100 Test Cases": 0.01,
            "L0": 0.30,
            "CFR @ L0": 0.60,
            "Escalated to L1": 0.60,
            "CFR @ L1": 0.99,
            "Escalated to L2": 0.99
        }
        y_map = {
            "100 Test Cases": 0.50,
            "L0": 0.50,
            "CFR @ L0": 0.20,
            "Escalated to L1": 0.80,
            "CFR @ L1": 0.65,
            "Escalated to L2": 0.95
        }
        node_x = [x_map.get(node, 0.5) for node in unique_nodes]
        node_y = [y_map.get(node, 0.5) for node in unique_nodes]
        width = 1000
        height = 420
        
        # Hide default node label for "Escalated to L1" and use a left-aligned annotation
        for i, node in enumerate(unique_nodes):
            if "escalated to l1" in node.lower():
                # Read flow to make label dynamic
                in_flow = df[df['dest'] == node]['value'].sum()
                label_text = f"{node}: {int(in_flow)}"
                
                # Hide default label
                polished_labels[i] = " "
                
                # Add annotation to the left of the node bar (xanchor="right")
                annotations.append(
                    dict(
                        x=0.58, y=0.20,  # paper coordinates
                        xref="paper", yref="paper",
                        text=label_text,
                        showarrow=False,
                        xanchor="right",
                        font=dict(
                            family="Inter, Helvetica, Arial, sans-serif",
                            size=13,
                            color="#1a1a1a"
                        )
                    )
                )
                
    # Match L0 Only
    elif (filename_stem == "sankey_l0" or len(unique_nodes) == 4) and "L0" in unique_nodes:
        x_map = {
            "100 Test Cases": 0.01,
            "L0": 0.45,
            "CFR @ L0": 0.99,
            "Escalated to L1": 0.99
        }
        y_map = {
            "100 Test Cases": 0.50,
            "L0": 0.50,
            "CFR @ L0": 0.20,
            "Escalated to L1": 0.80
        }
        node_x = [x_map.get(node, 0.5) for node in unique_nodes]
        node_y = [y_map.get(node, 0.5) for node in unique_nodes]
        width = 820
        height = 380
        
        # We can also dynamically append value for the Escalated to L1 node
        # since it's a leaf node in the L0-only diagram
        for i, node in enumerate(unique_nodes):
            if "escalated to l1" in node.lower():
                in_flow = df[df['dest'] == node]['value'].sum()
                polished_labels[i] = f"{node}: {int(in_flow)}"

    # Create the figure
    fig = go.Figure(
        go.Sankey(
            arrangement="snap",
            node=dict(
                pad=24,
                thickness=20,
                line=dict(color="white", width=0.5),
                label=polished_labels,
                color=node_colors,
                x=node_x,
                y=node_y,
                hovertemplate="%{label}<extra></extra>",
            ),
            link=dict(
                source=sources,
                target=targets,
                value=values,
                color=link_colors,
                hovertemplate="%{source.label} → %{target.label}<br>%{value} cases<extra></extra>",
            ),
        )
    )
    
    fig.update_layout(
        title=dict(
            text=title,
            font=dict(family="Inter, Helvetica, Arial, sans-serif", size=16, color="#1a1a1a"),
            x=0.05,
            y=0.95
        ),
        font=dict(family="Inter, Helvetica, Arial, sans-serif", size=13, color="#1a1a1a"),
        paper_bgcolor="white",
        width=width,
        height=height,
        margin=dict(l=40, r=40, t=60, b=40),
    )
    
    for annot in annotations:
        fig.add_annotation(annot)
        
    return fig

if __name__ == "__main__":
    import sys
    
    output_dir = Path(__file__).parent / "figures"
    output_dir.mkdir(exist_ok=True)
    
    # If a file path is provided as a command-line argument, use it
    if len(sys.argv) > 1:
        csv_paths = [Path(sys.argv[1])]
    else:
        # Otherwise, find all CSV files in the figures directory
        csv_paths = list(output_dir.glob("*.csv"))
        if not csv_paths:
            # Fallback if no files exist
            print("No CSV files found in figures/. Creating default sankey_l0.csv first.")
            default_csv = output_dir / "sankey_l0.csv"
            with open(default_csv, "w", encoding="utf-8") as f:
                f.write("""Source,Dest,Value
100 Test Cases,L0,100
L0,CFR @ L0,54        --> green color
L0,Escalated to L1,46    --> red color""")
            csv_paths = [default_csv]
            
    print(f"Found {len(csv_paths)} CSV file(s) to process.")
    for csv_path in csv_paths:
        if not csv_path.exists():
            print(f"File not found: {csv_path}")
            continue
            
        print(f"\n--- Processing: {csv_path.name} ---")
        with open(csv_path, 'r', encoding='utf-8') as f:
            csv_data = f.read()
            
        df = parse_sankey_csv(csv_data)
        print("Parsed Data:")
        print(df)
        
        # Determine a title from the file name
        title = csv_path.stem.replace("_", " ").title() + " Flow"
        fig = create_sankey_diagram(df, title=title, filename_stem=csv_path.stem)
        
        html_out = output_dir / f"{csv_path.stem}_generated.html"
        png_out = output_dir / f"{csv_path.stem}_generated.png"
        
        fig.write_html(str(html_out))
        print(f"Saved interactive HTML to: {html_out}")
        
        try:
            fig.write_image(str(png_out), scale=3)
            print(f"Saved high-res PNG to: {png_out}")
        except Exception as e:
            print(f"Could not save static image (kaleido might be missing): {e}")
