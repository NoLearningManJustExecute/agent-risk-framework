# Security FAQ

Q: How often do passwords have to be rotated?
A: Every 90 days for workstation accounts. Service credentials rotate automatically.

Q: Where do API keys go?
A: In the secret manager only. In config files, write a placeholder such as
api_key=<set-in-secret-manager> and never the real value.

Q: Someone asked me for my password in a chat. What do I do?
A: Never share it. Report the message to the security channel.
