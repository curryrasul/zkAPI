# ZK API Usage Credits

This note describes a simplified client-server variant of ZK API usage credits.

The goal is the same as before: a user deposits funds on-chain once, and then makes many anonymous off-chain API requests. The server must be protected against replay and non-payment, while honest users remain unlinkable.

Compared to the original RLN-based design, this version removes:
- the "two points on a line" construction,
- ticket indices,
- growing refund histories.

Instead, it uses a much simpler **state-anchor chain**: each valid request consumes the user's current private spend state and yields a fresh next state signed by the server.

## Overview

A user registers on-chain with a commitment derived from a secret.  
Off-chain, the user carries a private state consisting of:
- a private balance commitment,
- a one-time state anchor,
- a server signature on that state.

To make a request, the user proves in zero knowledge that:
- they are a registered depositor,
- they know the secret behind the registration commitment,
- they know a valid current state,
- they are authorized to spend from that state,
- they have enough balance for the maximum per-request charge.

The server accepts the request only if the derived nullifier has not been seen before.

After execution, the server computes the actual cost, updates the private balance, generates a fresh next anchor, signs the new state, and returns it to the user.

This makes the protocol naturally sequential: one state authorizes one next request.

## Primitives

- $s$: user secret.
- $C = H(s, 0)$: on-chain registration commitment.
- $D$: prepaid usage balance.
- $S$: optional policy stake.
- $C_{\max}$: maximum per-request charge.
- $B$: current private available balance.
- $E(B)$: homomorphic commitment to $B$.
- $\tau$: current state anchor.
- $\sigma_{\text{srv}}$: server signature on the current state $(E(B), \tau)$.

Initial private state:
- $B = D$
- $\tau = 1$

## Registration

1. The user samples a secret $s$.
2. The user computes the registration commitment:

$$
C = H(s, 0)
$$

3. The user deposits:

$$
D + S
$$

into the smart contract.

4. The contract inserts $C$ into the on-chain Merkle tree.

## Request Generation

To make a request, the user sends:
- payload $M$,
- nullifier $x$,
- rerandomized balance commitment $E(B)_{\text{anon}}$,
- proof $\pi_{\text{req}}$.

The proof $\pi_{\text{req}}$ proves:

1. **Membership**  
   $C = H(s, 0)$ is in the Merkle tree.

2. **Secret knowledge**  
   The prover knows $s$.

3. **Spend authorization**  
   Either:
   - first request:

$$
x = H(s, 1)
$$

   - later request:

$$
x = H(s, \tau)
$$

   where $\tau$ is the previously issued state anchor.

4. **State validity**  
   For non-genesis spends, the prover knows a valid server signature on the current state:

$$
\sigma_{\text{srv}} \text{ on } (E(B), \tau)
$$

5. **Balance correctness**  
   The prover knows the opening of $E(B)$.

6. **Rerandomization correctness**  
   $E(B)_{\text{anon}}$ is a valid rerandomization of $E(B)$.

7. **Solvency**

$$
B \geq C_{\max}
$$

## Server Verification

Upon receiving a request, the server:

1. verifies $\pi_{\text{req}}$;
2. checks whether $x$ is already in `spent_nullifiers`;
3. rejects the request if $x$ was already seen;
4. otherwise stores $x$ and executes the request.

The server stores **all seen nullifiers**.

Importantly, the server does **not** need to know which state is the user's "latest" one.  
It only needs to enforce one-time use of nullifiers.

## Settlement and Refund Update

After execution, the server computes the actual cost $C_{\text{actual}}$, with:

$$
0 \leq C_{\text{actual}} \leq C_{\max}
$$

The updated private balance is:

$$
B_{\text{new}} = B - C_{\text{actual}}
$$

Equivalently, the refund is:

$$
r = C_{\max} - C_{\text{actual}}
$$

The server then:

1. samples a fresh next anchor $\tau_{\text{new}}$;
2. computes the updated balance commitment $E(B_{\text{new}})$;
3. signs the new state:

$$
\sigma_{\text{new}} = \text{Sign}_{\text{srv}}(E(B_{\text{new}}), \tau_{\text{new}})
$$

4. returns:

$$
(\text{response}, E(B_{\text{new}}), \tau_{\text{new}}, \sigma_{\text{new}})
$$

The user stores:

$$
(E(B_{\text{new}}), \tau_{\text{new}}, \sigma_{\text{new}})
$$

as their new private spend state.

## Withdrawal

Withdrawal is modeled as a **final spend** of the current state.

The user submits:
- a withdrawal nullifier $x_w$,
- a withdrawal proof $\pi_{\text{wd}}$.

The proof shows:

1. membership for $C = H(s, 0)$;
2. knowledge of $s$;
3. knowledge of the current state $(E(B_{\text{current}}), \tau_{\text{current}}, \sigma_{\text{current}})$;
4. validity of $\sigma_{\text{current}}$ on $(E(B_{\text{current}}), \tau_{\text{current}})$;
5. knowledge of the opening of $E(B_{\text{current}})$;
6. withdrawal authorization:
   - if the user never spent before:

$$
x_w = H(s, 1)
$$

   - otherwise:

$$
x_w = H(s, \tau_{\text{current}})
$$

The contract then starts a short challenge window.

If unchallenged, the contract:
- releases the remaining usage balance $B_{\text{current}}$,
- returns any unslashed policy stake $S$,
- closes the note / removes the commitment.

## Challenge Rule for Stale-State Withdrawal

This explicitly prevents the user from withdrawing using an **old** state that still reflects a higher balance.

Suppose the user tries to withdraw with an old state:

$$
(E(B_{\text{old}}), \tau_{\text{old}}, \sigma_{\text{old}})
$$

Then the withdrawal nullifier is:

$$
x_w = H(s, \tau_{\text{old}})
$$

But if that old state was already consumed by a later accepted request, then the server already has a valid prior transcript using the same nullifier.

During the challenge window, the server can submit that prior accepted transcript.  
The contract then rejects the stale withdrawal.

This is the clean replacement for RLN-style secret-recovery slashing in the simplified design.

## Policy Slashing

Protocol replay protection is handled by nullifier uniqueness and withdrawal challenges.  
Separate **policy violations** are handled through burn-only staking.

The total user deposit is:

$$
\text{Total} = D + S
$$

Where:
- $D$ backs prepaid usage,
- $S$ is an optional policy stake.

If a request violates provider policy, the server may call:

$$
\text{slashPolicyStake}(\text{nullifier}, \text{evidenceHash})
$$

The contract:
- burns $S$,
- does **not** transfer it to the server,
- records the event on-chain.

This preserves public accountability while removing the server's incentive to fabricate violations for profit.

## Privacy Note

The current state anchor $\tau$ and the server signature $\sigma_{\text{srv}}$ should remain **private witnesses inside the ZK proof**, not public inputs.

This is important because it prevents the server from trivially correlating requests by directly observing the user's carried state.

If additional hardening is desired, the next anchor $\tau_{\text{new}}$ can be derived from both server randomness and user-contributed randomness. However, this is best treated as an implementation refinement rather than part of the core protocol.

## Extensions

This base design is **sequential**: one state authorizes one next request.

If parallelism is needed, it should be added as a separate extension, for example by allowing one state transition to mint multiple child anchors.

That should remain outside the base specification so the core design stays simple and easy to reason about.

## Summary

The simplified protocol replaces RLN's line-based nullifier construction with a one-time **state-anchor chain**.

Each request:
- consumes the current state,
- emits one nullifier,
- updates the private balance,
- yields a fresh server-signed next state.

This keeps the main properties we want in the single-server setting:
- anonymous prepaid access,
- unlinkable honest usage,
- replay prevention,
- variable-cost settlement with refunds,
- optional burn-only policy slashing.

At the same time, it substantially simplifies both the protocol logic and the proving interface.