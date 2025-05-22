# Compare with Expected Results

TLS-Anvil has the option to compare its test results with a set of expected results.
To do this, you will need an expected results file in JSON format.

Example `expected.json`:
``` json showLineNumbers
{
  "STRICTLY_SUCCEEDED" : [ 
    "XLF-ia3wstdqYe",
    "XLF-uQXeugeUkb"
  ],
  "CONCEPTUALLY_SUCCEEDED" : [ 
    "XLF-tSjRqK81S8", 
    "XLF-ujMXSAMmVF" 
  ],
  "FULLY_FAILED" : [
    "XLF-SA1CoksBgE",
    "XLF-NFYNXBgXk8"
  ],
  "PARTIALLY_FAILED" : [
    "XLF-4iPUuT51YH",
    "XLF-PkwVF7pRQa"
  ]
  "DISABLED" : [
    "XLF-CSQn3dUG9L",
    "XLF-Ax6kVTgheY"
  ]
}
```

You can then start TLS-Anvil with the `-expectedResults` flag as follows:
``` bash showLineNumbers
docker run \
    --rm \
    -it \
    --name tls-anvil \
    --network tls-anvil \
    -v $(pwd):/output/ \
    -v ./expected.json:/expected.json \
    ghcr.io/tls-attacker/tlsanvil:latest \
    -expectedResults /expected.json
    server \
    -connect localhost:8443        
```

TLS-Anvil will run all configured tests and at the end, it will compare
the actual results with the expected results from the file.
Tests that are not explicitly defined in the file, but have an actual
result of *STRICTLY_SUCCEEDED*, *CONCEPTUALLY_SUCCEEDED* or *DISABLED*
will not throw an error. All other deviations are printed out and will cause the
process to exit with exit code 1.
This is especially useful for CI testing.

After running a test, a `result_map.json` is generated in the output folder.
This file can be used as an input for expected results.
This can be useful for comparing results to the previous run.