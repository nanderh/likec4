---
'@likec4/core': patch
'@likec4/language-server': patch
'@likec4/diagram': patch
'@likec4/generators': patch
'likec4': patch
---

Elements and relationships can document known vulnerabilities (`vulnerability CVE-2024-3094 { severity critical ... }`) and STRIDE threats (`threat T-1 { stride spoofing, tampering ... }`), also through `extend`. Element details (also of deployed instances) get _Vulnerabilities_ and _Threats_ tabs with a STRIDE summary, the relationship popover lists threats of the data flow, nodes with unresolved items show a badge colored by the highest severity, and a _Color by_ menu in the navigation panel recolors the diagram by vulnerability severity or threat risk.

A _Threat register_ window in the navigation panel lists all threats and vulnerabilities of the project, with sorting and filtering on every column, navigation to the element or relationship in a view, and CSV export.

A _Security overview_ page (linked from the project overview and the sidebar) shows the register as a full page, with a risk matrix, counts by risk and STRIDE category, and the elements and relationships with the most open items. Clicking any of them filters the register, and rows expand to the full threat or vulnerability.

Node badges, _Color by_ and element details of a parent element include the threats and vulnerabilities of its children and of relationships between them, so a collapsed parent shows the risk inside it. Element details separate own items from items inherited from children. A scoped view that does not show its scope element (e.g. children in groups) shows the threats of that element and its relationships in a badge next to the view title.

Validation warns when the same threat or vulnerability id is defined on more than one element or relationship, or again in an `extend` of the same element. The warning for a relationship `extend` that matches no relationship lists the nearest relationships.

_Color by_ has a _Risk score_ mode: the highest likelihood × impact (1 - 16) of the unresolved threats, with the risk matrix in the legend.

Threats and vulnerabilities have an optional `source` property with one or more strings (`source 'Attestation', 'Questions'`), shown in element details and as a column of the threat register.

Accepted and transferred items count as _risk carried_, not as resolved: _Color by_ shows elements with only carried risk in their own color, and node badges show a second, muted marker for them.

Note: `threat` and `vulnerability` are now keywords and can no longer be used as element names or kinds.
