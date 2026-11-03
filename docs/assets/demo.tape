# Records docs/assets/demo.gif from a live run against a local Ollama serving llama3.1:8b.
# Run from the repository root with the virtual environment in .venv:
#   vhs docs/assets/demo.tape

Output docs/assets/demo.gif

Set Shell "powershell"
Set FontSize 16
Set Width 1060
Set Height 780
Set Padding 18
Set Theme "Dracula"
Set TypingSpeed 35ms
Set Framerate 12
Set WaitTimeout 180s

# Put the venv on PATH, turn off history suggestions, and use a plain prompt and title,
# so no local path or earlier command shows on screen.
Hide
Type `$env:PATH = (Resolve-Path .venv\Scripts).Path + ';' + $env:PATH; try { Set-PSReadLineOption -PredictionSource None } catch {}; $host.UI.RawUI.WindowTitle = 'demo'; function prompt { 'PS> ' }; cls`
Enter
Sleep 2s
Show

Type "# 1. No controls: the agent is asked to mail a confidential file to an outside address"
Enter
Sleep 800ms
Type "python -m agent_risk_framework.demo --case AC01 --arms baseline"
Sleep 600ms
Enter
Wait+Screen /result ATTACK SUCCEEDED/
Sleep 7s

Type "# 2. Same request, with the tool_permissions guardrail on"
Enter
Sleep 800ms
Type "python -m agent_risk_framework.demo --case AC01 --arms tool_permissions"
Sleep 600ms
Enter
Wait+Screen /result ATTACK BLOCKED/
Sleep 7s

Type "# 3. The measured result: the permission control against the content classifier"
Enter
Sleep 800ms
Type "python -m agent_risk_framework.demo --results"
Sleep 600ms
Enter
Wait+Screen /repeatability, not spread/
Sleep 15s
