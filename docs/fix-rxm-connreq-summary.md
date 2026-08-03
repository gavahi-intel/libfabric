# Fix: RXM TCP/RXM Data Mismatches on Directed Tagged Receives (Issue #11291)

## Problem

When using the TCP provider with the RXM utility provider (`FI_PROVIDER=tcp;ofi_rxm`),
concurrent sends from multiple clients combined with directed server receives (`FI_DIRECTED_RECV | FI_SOURCE`)
caused random data mismatches. With 128 clients, ~2119 mismatches were observed per test run
(~4000+ at 256 clients). The server would receive data from the **wrong** client — e.g., a
receive posted for client 26 with tag 26 would be satisfied by data from client 391.

## Root Cause

The RXM provider had two independent code paths that created `util_peer_addr` peer objects:

### Path 1 — AV Insert (correct)
When the application calls `fi_av_insert()`, the path in `rxm_av_insert()`:
1. Creates peer objects for each address
2. Assigns valid `fi_addr` handles (0, 1, 2, ..., N-1)
3. **Calls `rxm_av_foreach_ep()`** to register each peer with every endpoint's
   shared receive context (SRX), populating the indexed `src_trecv_queues[]` table

### Path 2 — TCP Connection Request (broken, now fixed)
When a client TCP-connects to the server, `rxm_process_connreq()`:
1. Extracts the client's ephemeral source address from the connection
2. Calls `util_get_peer()` which — because the ephemeral port differs from the
   registered AV address — creates a **new** peer object with `fi_addr = FI_ADDR_NOTAVAIL`
3. **DID NOT call `rxm_av_foreach_ep()`** — the new peer was never registered
   with endpoint SRX contexts

### Consequence
When a packet arrived from such an unregistered peer:
- `match.addr = conn->peer->fi_addr` resolved to `FI_ADDR_NOTAVAIL` (effectively `FI_ADDR_UNSPEC`)
- The SRX could not find an indexed per-source receive queue
- The packet fell into the **shared unexpected-tag queue**
- Under concurrent load, packets from multiple clients collided in this shared queue
- Server receives for one client were satisfied by data from another client

### Proof (from debug logs, same-process evidence)
```
PM pid=3096752 idx=1 fa=1              ← AV insert: fi_addr correctly assigned
CR pid=3096752 idx=1 fa=ffffffffffffffff  ← Connreq: same peer index, fi_addr unresolved
RS pid=3096752 conn=1 ra=ffffffffffffffff  ← Receive: unresolved addr → shared queue
```

## Fix

Three files changed:

### 1. `prov/util/src/rxm_av.c`
Added a new helper function `rxm_av_foreach_ep()` that iterates all endpoints
bound to an AV and invokes the registration callback for each:

```c
void rxm_av_foreach_ep(struct util_av *av)
{
    struct dlist_entry *av_entry;
    struct util_ep *util_ep;
    struct rxm_av *rxm_av = container_of(av, struct rxm_av, util_av);

    if (!rxm_av->foreach_ep)
        return;

    dlist_foreach (&av->ep_list, av_entry) {
        util_ep = container_of(av_entry, struct util_ep, av_entry);
        rxm_av->foreach_ep(av, util_ep);
    }
}
```

Refactored `rxm_av_insert()` to call this helper instead of the inline loop.

### 2. `prov/rxm/src/rxm_conn.c`
In `rxm_process_connreq()`, added a call to `rxm_av_foreach_ep()` immediately
after `rxm_add_conn()` succeeds:

```c
conn = rxm_add_conn(ep, peer);
if (!conn)
    goto remove;

/* Register newly allocated peer with all endpoints' receive contexts
 * so that directed receives can find the correct peer->fi_addr mapping.
 */
rxm_av_foreach_ep(&av->util_av);
```

### 3. `include/ofi_util.h`
Added declaration of `rxm_av_foreach_ep()`.

## Why the Fix Works

After the fix, every peer — whether created via AV insert or TCP connreq — is
registered with all endpoint SRX contexts. Each peer gets a valid `fi_addr`
index, and packets arriving from that peer are routed to the correct indexed
`src_trecv_queues[fi_addr]` entry instead of the shared unexpected queue.
This ensures directed receives exclusively match packets from their intended source.

## Test Results

Reproducer: 128 concurrent clients, each sending a tagged message to the server
which posts a directed receive matching the sending client's `fi_addr` and tag.

| State        | Mismatches (128 clients) |
|--------------|--------------------------|
| Before fix   | ~2119 per run            |
| After fix    | **0**                    |

## Reproducer

Located at `~/work/rxm_repro/` on the development machine.
Build and run:
```bash
cd ~/work/rxm_repro
LD_LIBRARY_PATH=~/work/libfabric/src/.libs ./reproducer 128 1
```

## Debugging Approach (for reference)

Three rounds of instrumentation were used to narrow down the root cause:

1. **Round 1** — Added `rxm_dbg_log_recv_match()` helper and traces in
   `rxm_handle_recv_comp()` and `rxm_unexp_start()` to log conn_id, resolved
   addr, match addr, tag, and unexpected-queue flag per receive.

2. **Round 2** — Added `recv-setup` traces logging capability flags, msg_srx
   state, connection lookup result, conn_state, and resolved fi_addr at the
   point where `match.addr` is assigned before calling `get_tag()`.

3. **Round 3** — Added `peer-get`, `peer-map`, and `connreq-peer` traces in
   `rxm_av.c` and `rxm_conn.c` to audit peer identity (index, fi_addr, refcnt)
   across both allocation paths, revealing same-process peers with matching index
   but divergent fi_addr values.

All debug traces were removed before final commit; only the functional fix remains.
