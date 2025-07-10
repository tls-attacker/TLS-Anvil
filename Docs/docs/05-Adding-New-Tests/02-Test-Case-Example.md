import Definition from '@site/src/components/Definition';

# Test Template Example

This section presents an example of a test template.  
The template is designed to verify whether the <Definition id="SUT" /> sends the correct TLS alert when the CBC padding is invalid. This test applies to both clients and servers by modifying the first application message to include invalid padding. The template executes only if the SUT supports a CBC Cipher Suite; otherwise, it is skipped. The padding error is injected at multiple positions, determined through combinatorial testing.

### Annotations

* Line 1: Generic `AnvilTest` annotation that activates the Anvil-Core test execution lifecycle. Additionally, basic parameters are automatically added to the <Definition id="IPM" />. A unique test ID is assigned and referenced in the test metadata.
* Lines 2-5: These annotations modify the IPM:
  * Line 2: Specifies a different default IPM model.
  * Line 3: Adds extra parameters to the IPM.
  * Line 4: Adds a constraint on the Cipher Suite parameter so the test runs only when a CBC Cipher Suite is selected. This uses the `isCBC` method from the TLS-Attacker Cipher Suite enum.
  * Line 5: Adds a constraint on the Record Length parameter. The `recordLengthAllowsModification` method (defined on line 43) is invoked with the selected value as argument.

### Test Function

* Line 7: This line is part of nearly every test case. It generates the TLS-Attacker `Config`, which defines how the TLS-Attacker Server/Client behaves (e.g., algorithms offered).
* Lines 8-12: A bitmask is generated and XORed with the padding. During parameter value generation, a byte and bit position are chosen by the combinatorial testing algorithm. The bitmask is created dynamically during test execution.
* Lines 14-15: An application message is created, and its padding is invalidated. The message is obtained from the config inside the `AppMsgLengthDerivation.applyToConfig` method.
* Lines 17-21: A TLS-Attacker `WorkflowTrace` is generated to perform a complete handshake and send the application message afterward.
* Lines 23-29: The WorkflowTrace is scheduled for execution. Once the handshake completes, a lambda function runs to determine the test result for a single <Definition id="test case" />. The overall template result is based on all individual test case outcomes.

```java showLineNumbers
@AnvilTest(id = "5246-RNB9LX21i9")
@ModelFromScope(modelType = "CERTIFICATE")
@IncludeParameters({@IncludeParameter("APP_MSG_LENGTH"), @IncludeParameter("PADDING_BITMASK")})
@ValueConstraints({@ValueConstraint(identifier = "CIPHER_SUITE", method = "isCBC")})
@DynamicValueConstraints(affectedIdentifiers = "RECORD_LENGTH", methods = "recordLengthAllowsModification")
public void invalidCBCPadding(AnvilTestCase testCase, WorkflowRunner runner) {
    Config c = getPreparedConfig(runner);
    byte[] modificationBitmask = parameterCombination.buildBitmask();

    Record record = new Record();
    record.setComputations(new RecordCryptoComputations());
    record.getComputations().setPadding(Modifiable.xor(modificationBitmask, 0));

    ApplicationMessage appData = new ApplicationMessage();
    appData.setData(Modifiable.explicit(c.getDefaultApplicationMessageData().getBytes()));

    SendAction sendAction = new SendAction(appData);
    sendAction.setRecords(record);

    WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
    workflowTrace.addTlsActions(sendAction, new ReceiveAction(new AlertMessage()));

    runner.execute(workflowTrace, c).validateFinal(i -> {
        WorkflowTrace trace = i.getWorkflowTrace();
        Validator.receivedFatalAlert(i);

        AlertMessage msg = trace.getFirstReceivedMessage(AlertMessage.class);
        Validator.testAlertDescription(i, AlertDescription.BAD_RECORD_MAC, msg);
    });
}

public boolean recordLengthAllowsModification(Integer lengthCandidate) {
    return lengthCandidate >= 50;
}
```

### Metadata

Each test requires a metadata entry stored in `src/main/resources/metadata.json`. A typical entry includes:

* The metadata file is a JSON object where each key corresponds to a test ID.
* Line 2: The test template ID (see [Test Function](#test-function)).
* Line 3: A description extracted from the RFC.
* Lines 4-10: Categories and severity levels assigned to each test. These influence the scoring based on test results. Due to subjectivity, categories and severity levels are not detailed in our USENIX Security paper.
* Lines 11-14 (optional): Referenced RFC number and section.
* Lines 15-21 (optional): Tags used for searching test results.

```json showLineNumbers
{
    "5246-RNB9LX21i9": {
        "description": "Each uint8 in the padding data vector MUST be filled with the padding length value. The receiver MUST check this padding and MUST use the bad_record_mac alert to indicate padding errors.",
        "severityLevels": {
            "Crypto": 100,
            "Security": 80,
            "RecordLayer": 100,
            "Interoperability": 80,
            "Alert": 80
        },
        "rfc": {
            "number": 5246,
            "section": "6.2.3.2 CBC Block Cipher"
        },
        "tags": [
            "both",
            "tls12",
            "rfc5246",
            "CBCBlockCipher",
            "invalidCBCPadding"
        ]
    }
}
```
