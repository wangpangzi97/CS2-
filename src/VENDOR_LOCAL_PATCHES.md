# Local vendor adapter (2026-10-20 follow-up)
Base: demoinfocs-golang/v6 v6.0.0-alpha.2, MIT. Existing upstream files remain unchanged.
Added: vendor/github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/sendtables/radar_checkpoint.go.
Detached entity-field checkpoints support live acknowledged-tick delta baselines. Entity callbacks are unsupported.
Decoder history: <=128 states, <=128MiB conservatively estimated checkpoint state, <=32MiB per state.
These are accounting bounds, not a total-process heap guarantee. The module HTTPS h1 authenticated original upstream contents, NOT this added file; source manifest hashes cover local additions.
Do not regenerate vendor without reapplying this adapter. No game-process access is performed by the adapter.
