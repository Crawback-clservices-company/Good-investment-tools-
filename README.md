# Good-investment-tools-
Verifica cualquier compañía  donde vayamos a invertir 

## Motor de riesgo
- `risk_engine.analyze(source_code, whitepaper)`: reporte de riesgo heurístico.
- `risk_engine.proofs`: hash SHA-256 canónico del reporte, anclado en una blockchain (`EvmRpcAnchor`, JSON-RPC EVM) o en un ledger local (`LocalLedger`); `verify_report` detecta cualquier alteración.
- `risk_engine.agent_tool`: herramienta para agentes de IA (`TOOL_SCHEMA`, `assess_platform`). CLI: `python -m risk_engine.agent_tool --code contrato.sol --whitepaper wp.txt`.
