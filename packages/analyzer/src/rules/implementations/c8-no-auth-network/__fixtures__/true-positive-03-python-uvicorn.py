# True positive: Python uvicorn.run with host wildcard and no auth
# guard wired anywhere in the file. The MCP server tool endpoints are
# exposed unauthenticated. The detector recognises wildcard binding
# without an auth marker and reports a high-severity finding.
import uvicorn
from fastapi import FastAPI

app = FastAPI()

@app.post("/tool")
def call_tool(payload: dict) -> dict:
    return {"ok": True}

def main() -> None:
    uvicorn.run(app, host="0.0.0.0", port=8080)
