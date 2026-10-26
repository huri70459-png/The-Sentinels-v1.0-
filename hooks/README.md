# Sentinel hook wiring (Stage 3 boundary)

## Claude Code (`settings.json`)
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|Bash",
        "hooks": [
          {
            "type": "command",
            "command": "C:/Python314/python.exe hooks/sentinel_pretooluse.py",
            "env": {
              "SENTINEL_WORKTREE": "<absolute worktree path from sentinel_init_task>",
              "SENTINEL_ALLOWED": "src/*.py,src/*.html"
            }
          }
        ]
      }
    ]
  }
}
```

## Cursor (`settings.json` → hooks)
Use `preToolUse` for Write/Edit/Shell pointing at the same script.
Invalid/deny responses (exit 2) block the action.
