# Architecture

Source
 -> signature anchors
 -> fragment inventory
 -> candidate graph
 -> edge scoring
 -> bounded path search
 -> conflict resolution
 -> confidence classification
 -> reconstruction plan
 -> extraction

A graph node is a candidate fragment.
An edge means "fragment B is a plausible continuation of A."

Edge evidence:
- physical adjacency
- expected next file offset
- format-specific continuation
- cluster alignment
- content validation
- size/termination consistency

The graph search is bounded. This is deliberate: unconstrained combinatorial
search can become computationally explosive and produce convincing nonsense.

Confidence classes:
90-100  strong
70-89   probable
50-69   weak
<50     rejected
