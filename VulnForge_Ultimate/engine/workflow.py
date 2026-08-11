from typing import List
from core.container import context
from httpclient.engine import HttpEngine # Updated Elite Client

class WorkflowEngine:
    """Executes multi-step logic chains."""
    def __init__(self):
        self.http = context.resolve(HttpEngine)
        self.memory = {}

    async def execute_step(self, step_definition: dict, target: str):
        # 1. Variable Substitution (e.g. {{auth_token}})
        path = self._interpolate(step_definition['path'])
        
        # 2. Execution
        resp = await self.http.execute(step_definition['method'], f"{target}{path}")
        
        # 3. Extraction for next step
        if 'extract' in step_definition:
            val = self._extract(resp, step_definition['extract'])
            self.memory[step_definition['extract']['name']] = val
            
        return resp

    def _interpolate(self, text: str) -> str:
        for k, v in self.memory.items():
            text = text.replace(f"{{{{{k}}}}}", str(v))
        return text
