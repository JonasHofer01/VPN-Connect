"""Fix f-string escaping issues in the redesigned main tab section only."""

with open(r"c:\Users\jonas\PycharmProjects\PythonProject\vpn_connect.py", "r", encoding="utf-8") as f:
    content = f.read()

# The redesigned code block (lines ~1419-1620) has wrong f-string escaping.
# In f-strings: {{ becomes literal {, so {{{{ becomes literal {{
#               {expr} evaluates expr, but {{expr}} becomes literal {expr}
# 
# What we generated: QFrame {{{{ ... {{C['card']}} ... }}}}
# What we need:      QFrame {{ ... {C['card']} ... }}
#
# So: {{{{ -> {{, }}}} -> }}, {{C[...']}} -> {C[...']}

# Find the redesigned section boundaries
start = content.index("        # Haupt-Tab\n")
end = content.index("        main_tab_layout.addStretch()\n") + len("        main_tab_layout.addStretch()\n")

section = content[start:end]

# Fix quadruple braces -> double braces (for CSS selectors in f-strings)
section = section.replace("{{{{", "{{")
section = section.replace("}}}}", "}}")

# Fix double-braced variable references -> single braces
import re
section = re.sub(r"\{\{(C\['[^']+'\])\}\}", r"{\1}", section)

content = content[:start] + section + content[end:]

with open(r"c:\Users\jonas\PycharmProjects\PythonProject\vpn_connect.py", "w", encoding="utf-8") as f:
    f.write(content)

print("f-string escaping fixed.")
