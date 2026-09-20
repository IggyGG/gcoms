# Minimal Rust application integrations

Implement the retained application API on the current GComs trunk and migrate
GChat to consume it. Two explicit feature sets share messaging, channels and
file sharing: `ipc,files` for an existing host and
`embedded,files,gc2-carrier` for an in-process runtime/relay.

Implemented; validation in progress:
- Merge retained API/runtime work with current GC/2 profile 22 and persistence.
- Make typed RPC, journal dependencies and daemon launch opt-in; preserve unwind.
- Move the transfer worker into GComs; retain GChat's cache path/key and UI adapter.
- Append file sharing and network status in IPC18; preserve preceding tags.
- Add independent consumer, graph checks, native executable size measurements.

Pending: finish regression and combined-source gates, native Linux/macOS size
qualification, documentation with measured results, and land the paired changes.
