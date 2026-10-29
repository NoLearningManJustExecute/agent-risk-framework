# Records docs/demo/demo.gif from a live run against a local Ollama serving llama3.1:8b.
# Run from the repository root with the virtual environment in .venv:
#   vhs docs/demo/demo.tape

Output docs/demo/demo.gif

Set Shell "powershell"
Set FontSize 14
Set Width 900
Set Height 660
Set Padding 18
Set Theme "Dracula"
Set TypingSpeed 35ms
Set Framerate 12
Set WaitTimeout 120s

# Put the venv on PATH and use a plain prompt, so no local path shows on screen.
Hide
Type `$env:PATH = (Resolve-Path .venv\Scripts).Path + ';' + $env:PATH; function prompt { '$ ' }; cls`
Enter
Sleep 2s
Show

Type "# AC01, live against llama3.1:8b: no controls, tool_permissions, then all six"
Enter
Sleep 800ms
Type "python -m agent_risk_framework.demo --case AC01"
Sleep 600ms
Enter
Wait+Screen /credited to approval_gate, tool_permissions/
Sleep 8s
