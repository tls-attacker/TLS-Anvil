import Definition from '@site/src/components/Definition';

# Test Template Example

In the following we want to discuss a test template example.
This template aims to test if the <Definition id="SUT" /> sends the correct TLS alert, if the CBC padding is incorrect. This test works for client and servers by changing the first application message to use an invalid padding. The template is only executed when the SUT supports a CBC Cipher Suite, otherwise it is skipped. The padding error is injected into multiple positions. The positions are determined by combinatorial testing.

### Annotations

* Line 1: Generic `AnvilTest` annotation that activates the Anvil-Core test execution lifecycle. In addition basic parameters are added automatically to the <Definition id="IPM" />. An id is also given, which has to be unique and will be referenced in the test metadata.
* Line 2-5: Those annotations modify the IPM
  * Line 2: Changes the default IPM model
  * Line 3: Adds additional parameters to the IPM
  * Line 4: Adds a constraint to the Cipher Suite parameter of the IPM, so that the test only runs when a CBC Cipher Suite is selected. The `isCBC` method is called on the TLS-Attacker Cipher Suite enum.
  * Line 5: Adds a constraint to the Record Length parameter. The `recordLengthAllowsModification` method is called on the current class (line 43), given the selected value as argument.

### Test function

* Line 7: This is line basically part of every test case, it generates the TLS-Attacker `Config` that defines how the TLS-Attacker Server/Client should behave (e.g. which algorithms are offered, etc.)
* Line 8-12: A bitmask is generated that xored on the padding. During the parameter value generation a byte and bit position is chosen by the combinatorial testing algorithm. From those positions the bitmask is generated during the test execution.
* Line 14-15: An application message is created from which the padding is invalidated. The message that is received from the config is set inside the `AppMsgLengthDerivation.applyToConfig` method.
* Line 17-21: A TLS-Attacker `WorkflowTrace` is generated that performs a complete handshake and sends an application message after the handshake.
* Line 23-29: The WorkflowTrace is scheduled to be sent. After the handshake is completed, the lambda function get's executed that determines the test result for a single <Definition id="test case" />. The result of the test template is determined by all test case results.

```java showLineNumbers
@AnvilTest(id = "5246-RNB9LX21i9")
@ModelFromScope(modelType = "CERTIFICATE")
@IncludeParameters({@IncludeParameter("APP_MSG_LENGHT"), @IncludeParameter("PADDING_BITMASK")})
@ValueConstraints({@ValueConstraint(identifier = "CIPHER_SUITE", method = "isCBC")})
@DynamicValueConstraints(affectedIdentifiers = "RECORD_LENGTH", methods = "recordLengthAllowsModification")
public void invalidCBCPadding(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
    Config c = getPreparedConfig(argumentAccessor, runner);
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
A metadata entry has to be provided for every test. It is stored in `src/main/resources/metadata.json`. A basic entry looks like this:

* The metadata file is a json object which keys are the test ids.
* Line 2: Id of the test template (see [Test function](#test-function)).
* Line 3: A description taken from the RFC.
* Line 4-10: Each test can have categories and a severity levels. Depending on the test result, a score is calculated for each test. Since it is not possible to choose the categories and severity levels objectively, those are not mentioned in our USENIX Security paper.
* Line 11-14: (optional) Referenced RFC number and section.
* Line 15-21: (optional) Tags used for searching test results.

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
    },
}
```
