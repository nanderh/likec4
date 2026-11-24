---
'@likec4/core': patch
'@likec4/language-server': patch
'@likec4/diagram': patch
'@likec4/generators': patch
'likec4': patch
---

Elements and relationships can document known vulnerabilities (`vulnerability CVE-2024-3094 { severity critical ... }`) and STRIDE threats (`threat T-1 { stride spoofing, tampering ... }`), also through `extend`. Element details (also of deployed instances) get _Vulnerabilities_ and _Threats_ tabs with a STRIDE summary, the relationship popover lists threats of the data flow, nodes with unresolved items show a badge colored by the highest severity, and a _Color by_ menu in the navigation panel recolors the diagram by vulnerability severity or threat risk.

A _Threat register_ window in the navigation panel lists all threats and vulnerabilities of the project, with sorting and filtering on every column, navigation to the element or relationship in a view, and CSV export.

Node badges, _Color by_ and element details of a parent element include the threats and vulnerabilities of its children and of relationships between them, so a collapsed parent shows the risk inside it. Element details separate own items from items inherited from children.

Accepted and transferred items count as _risk carried_, not as resolved: _Color by_ shows elements with only carried risk in their own color, and node badges show a second, muted marker for them.

Note: `threat` and `vulnerability` are now keywords and can no longer be used as element names or kinds.
