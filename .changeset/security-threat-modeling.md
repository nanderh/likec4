---
'@likec4/core': patch
'@likec4/language-server': patch
'@likec4/diagram': patch
'@likec4/generators': patch
'likec4': patch
---

Elements and relationships can document known vulnerabilities (`vulnerability CVE-2024-3094 { severity critical ... }`) and STRIDE threats (`threat T-1 { stride spoofing, tampering ... }`), also through `extend`. Element details (also of deployed instances) get _Vulnerabilities_ and _Threats_ tabs with a STRIDE summary, the relationship popover lists threats of the data flow, nodes with unresolved items show a badge colored by the highest severity, and a _Color by_ menu in the navigation panel recolors the diagram by vulnerability severity or threat risk.

Note: `threat` and `vulnerability` are now keywords and can no longer be used as element names or kinds.
