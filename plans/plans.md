# 🔥 PHASE 1 — Make detectors *actionable*

Right now detectors probably:
• print warnings
• point to instruction
• maybe dump tx hash

That’s not enough for bounties.

We upgrade detectors to output:
✔ concrete calldata
✔ concrete sender
✔ concrete value
✔ concrete path
✔ exploit classification

### Upgrade 1: Detector result object

Add a unified result schema:

```python
class ExploitFinding:
    def __init__(self, kind, description, tx, state):
        self.kind = kind
        self.description = description
        self.tx = tx
        self.sender = tx.caller
        self.data = tx.data
        self.value = tx.value
        self.pc = state.cpu.pc
```

Then detectors return `ExploitFinding` instead of printing.

---

# 🔥 PHASE 2 — Add exploit PoC generator

For every finding:
Generate a minimal Python script that replays it.

Example output:

```python
from web3 import Web3
w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

tx = {
    "from": "0x123...",
    "to": "0xABC...",
    "data": "0xa9059cbb000000...",
    "value": 0
}
w3.eth.send_transaction(tx)
```

This is HUGE for bounties.

---

# 🔥 PHASE 3 — Add real bug classes

Right now you have:
✔ auth bypass
✔ invariant breaks

Next detectors to add:

### A) Storage Corruption

Detect:

```solidity
mapping(address => uint) balances;
function withdraw(uint i) { balances[msg.sender] -= i; }
```

but path allows:
`balances[attacker] < i`

Detector logic:

```
if symbolic_storage_write to critical slot
and constraint allows underflow
→ report
```

---

### B) Call Order Dependency (MEV)

Detect:

```
function buy() public {
  price = oracle();
  balances[msg.sender] += amount;
}
```

If oracle is:
• mutable
• external
• symbolic

Then:
→ sandwich exploit possible

---

### C) Dangerous delegatecall

Detect:

```
delegatecall(user_supplied_address)
```

If address is symbolic:
→ instant critical

---

# 🔥 PHASE 4 — Speed hacks (big payoff)

Add:
✔ state hashing (prune equivalent states)
✔ gas-guided path priority
✔ depth cutoff heuristics
✔ constraint slicing per function

This is how you go from:
10 minutes → 30 seconds

---

# 🧠 PHASE 5 — Exploit minimization

When exploit found:
Try to reduce calldata:

```
while exploit still holds:
  remove calldata byte
```

This produces:
✔ smallest exploit
✔ easiest reproduction
✔ clean report

