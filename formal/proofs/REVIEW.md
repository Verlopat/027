# Independent proof sign-off — outstanding

No external cryptographer has reviewed T1–T8. The `.tex` files in this
folder are working proof sketches with explicitly identified gaps.
**None are claimed as proved**. Before publication, require a signed,
versioned review naming the reviewer, files/commit SHA, definitions,
fixed bugs, residual assumptions and formal verification outputs.

The security bounds for silent suppression REQUIRE trusted freshness;
`tests/v2/test_adversary.py` contains the witness-free counterexample.

Tamarin status: draft model only, no local executable, no checked lemmas.
