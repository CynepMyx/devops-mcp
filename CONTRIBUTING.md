# Contributing

Contributions are welcome. Please keep them focused and practical.

## How to Contribute

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-tool`
3. Make your changes
4. Test inside the container: `docker exec -w /app devops-mcp python3 your_test.py`
5. Open a pull request with a clear description

## Adding a New Tool

1. Create `tools/your_tool.py` with an `async def your_tool(args: dict) -> dict` function
2. Add validation logic to `security.py` if needed
3. Register in `server.py`:
   - Import at the top
   - Add to `_TOOL_MODULES` list (for hot reload)
   - Add `Tool(...)` definition to `_TOOLS`
   - Add to `_DISPATCH` dict
4. Document in `README.md`

## Code Style

- Python 3.12+
- No external formatters required, but keep it readable
- All tool functions must return `dict` (never raise exceptions to the caller)
- Dangerous operations must require `confirmed=true`

## Security Guidelines

- Never add tools that bypass the security layer in `security.py`
- All new SSH/file/DB operations must go through validation
- Destructive actions must require explicit confirmation
