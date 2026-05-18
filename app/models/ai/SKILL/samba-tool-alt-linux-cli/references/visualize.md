# samba-tool visualize — Graphical Representations of Samba Network State

Produce graphical representations of Samba network state, particularly replication topology.

## Synopsis

```bash
samba-tool visualize [options] <subcommand>
```

## Description

To understand what is happening in a replication graph, it is sometimes helpful to use visualizations. The `visualize` command provides several modes to represent the Samba AD network state graphically.

## Subcommands (Modes of Operation)

### visualize ntdsconn
Look at NTDS connections between domain controllers.

```bash
samba-tool visualize ntdsconn [options]
```

### visualize reps
Look at repsTo and repsFrom objects.

```bash
samba-tool visualize reps [options]
```

### visualize uptodateness
Look at replication lag as shown by the uptodateness vectors.

```bash
samba-tool visualize uptodateness [options]
```

## Graphical Modes

| Option | Description |
|--------|-------------|
| `--distance` | Show distances between DCs in a matrix in the terminal |
| `--dot` | Generate Graphviz dot output (for `ntdsconn` and `reps` modes). Shows the network as a graph with DCs as vertices and connections as edges. Degenerate edges are shown in different colours or line-styles |
| `--xdot` | Generate Graphviz dot output and attempt to view it immediately using `/usr/bin/xdot` |

## Options

| Option | Description |
|--------|-------------|
| `-r` | Contact all DCs known to the first database (necessary for `uptodateness` and `reps` modes because repsFrom/To objects are not replicated) |
| `-H, --URL=URL` | LDB URL for database or target server |
| `-U, --user=USER` | Username for authentication |
| `--password=PASSWORD` | Password for authentication |

## Examples

### Visualize NTDS connections
```bash
# Show as distance matrix
samba-tool visualize ntdsconn --distance

# Generate dot output for Graphviz
samba-tool visualize ntdsconn --dot > ntdsconn.dot

# View with xdot
samba-tool visualize ntdsconn --xdot
```

### Visualize replication partners
```bash
# Show repsFrom/repsTo as distance matrix
samba-tool visualize reps --distance

# Generate dot output
samba-tool visualize reps --dot > reps.dot

# Contact all DCs (recommended for reps mode)
samba-tool visualize reps -r --dot > reps.dot
```

### Visualize replication lag
```bash
# Show uptodateness as distance matrix
samba-tool visualize uptodateness --distance -r

# Generate dot output
samba-tool visualize uptodateness --dot -r > uptodateness.dot
```

### Render dot file to image
```bash
# After generating a .dot file, render to PNG
dot -Tpng ntdsconn.dot -o ntdsconn.png

# Render to SVG
dot -Tsvg reps.dot -o reps.svg

# Render to PDF
dot -Tpdf uptodateness.dot -o uptodateness.pdf
```

## Typical Workflows

### Diagnose replication topology
```bash
# 1. Visualize NTDS connections
samba-tool visualize ntdsconn --distance

# 2. Check replication lag
samba-tool visualize uptodateness --distance -r

# 3. Generate detailed graph
samba-tool visualize reps -r --dot > replication-graph.dot
dot -Tpng replication-graph.dot -o replication-graph.png
```

### Compare topology between DCs
```bash
# Check from DC1's perspective
samba-tool visualize ntdsconn --distance -H ldap://dc1.example.com

# Check from DC2's perspective
samba-tool visualize ntdsconn --distance -H ldap://dc2.example.com
```
