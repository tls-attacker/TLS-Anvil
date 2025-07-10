# Compare with Expected Results

TLS-Anvil supports verifying test outcomes by comparing them against a set of **expected results**. This is especially useful in **CI/CD pipelines** to detect regressions or unexpected behavior changes.

---

## Expected Results Format

The expected results must be defined in a **JSON file** mapping test IDs to expected outcomes.

```json showLineNumbers title="expected.json"
{
  "STRICTLY_SUCCEEDED": [ 
    "XLF-ia3wstdqYe",
    "XLF-uQXeugeUkb"
  ],
  "CONCEPTUALLY_SUCCEEDED": [ 
    "XLF-tSjRqK81S8", 
    "XLF-ujMXSAMmVF" 
  ],
  "FULLY_FAILED": [
    "XLF-SA1CoksBgE",
    "XLF-NFYNXBgXk8"
  ],
  "PARTIALLY_FAILED": [
    "XLF-4iPUuT51YH",
    "XLF-PkwVF7pRQa"
  ],
  "DISABLED": [
    "XLF-CSQn3dUG9L",
    "XLF-Ax6kVTgheY"
  ]
}
```

> ⚠️ Make sure your JSON is valid (e.g. commas between entries). The above format groups test IDs by expected result category.

---

## Running with Expected Results

You can pass the expected results file using the `-expectedResults` parameter:

```bash showLineNumbers title="Run with Expected Results"
docker run \
    --rm \
    -it \
    --name tls-anvil \
    --network tls-anvil \
    -v $(pwd):/output/ \
    -v ./expected.json:/expected.json \
    ghcr.io/tls-attacker/tlsanvil:latest \
    -expectedResults /expected.json \
    server \
    -connect localhost:8443
```

---

## Behavior and Exit Codes

- TLS-Anvil runs all configured tests and compares the actual results to those in the expected results file.
- **Accepted deviations**:
    - Tests *not listed* in the file that result in `STRICTLY_SUCCEEDED`, `CONCEPTUALLY_SUCCEEDED`, or `DISABLED` are **ignored** (do not trigger errors).
- **Failing deviations**:
    - Any other mismatch causes TLS-Anvil to:
        - Print a detailed difference report
        - Exit with **code `1`**

This behavior is designed for integration with automated testing environments.

---

## Auto-Generating Expected Results

After a test run, TLS-Anvil produces a file:

```bash
/output/result_map.json
```

This file contains the actual result mapping of all executed tests and can be reused as an **input for future expected results**. This enables automated tracking of test regressions between runs.

---
