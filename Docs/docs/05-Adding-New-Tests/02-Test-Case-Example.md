import Definition from '@site/src/components/Definition';

# Test Template Example

In the following we want to discuss a test template example.
This template aims to test if the <Definition id="SUT" /> sends the correct TLS alert, if the CBC padding is incorrect. This test works for client and servers by changing the first application message to use an invalid padding. The template is only executed when the SUT supports a CBC Cipher Suite, otherwise it is skipped. The padding error is injected into multiple positions. The positions are determined by combinatorial testing.


### Annotations
* Line 1: Generic `TlsTest` annotation that activates the TLS-Anvil test execution lifecycle. In addition basic parameters are added automatically to the <Definition id="IPM" />.
* Line 5-8: Those annotations modify the IPM
    * Line 5: Changes the default IPM model
    * Line 6: Adds additional parameters to the IPM
    * Line 7: Adds a constraint to the Cipher Suite parameter of the IPM, so that the test only runs when a CBC Cipher Suite is selected. The `isCBC` method is called on the TLS-Attacker Cipher Suite enum.
    * Line 8: Adds a constraint to the Record Length parameter. The `recordLengthAllowsModification` method is called on the current class (line 43), given the selected value as argument.
* Line 9-13: Each test is annotated with categories and a severity level. Depending on the test result, a score is calculated for each test. Since it is not possible to choose the categories and severity levels objectively, those are not mentioned in our USENIX Security paper.

### Test function
* Line 15: This is line basically part of every test case, it generates the TLS-Attacker `Config` that defines how the TLS-Attacker Server/Client should behave (e.g. which algorithms are offered, etc.)
* Line 17-18: An application message is created from which the padding is invalidated. The message that is received from the config is set inside the `AppMsgLengthDerivation.applyToConfig` method.
* Line 20-24: A bitmask is generated that xored on the padding. During the parameter value generation a byte and bit position is chosen by the combinatorial testing algorithm. From those positions the bitmask is generated during the test execution.
* Line 26-33: A TLS-Attacker `WorkflowTrace` is generated that performs a complete handshake and sends an application message after the handshake.
* Line 35-41: The WorkflowTrace is scheduled to be sent. After the handshake is completed, the lambda function get's executed that determines the test result for a single <Definition id="test case" />. The result of the test template is determined by all test case results.

```java showLineNumbers
@TlsTest(description = "Each uint8 in the padding data " +
        "vector MUST be filled with the padding length value. The receiver " +
        "MUST check this padding and MUST use the bad_record_mac alert to " +
        "indicate padding errors.")
@ModelFromScope(baseModel = ModelType.CERTIFICATE)
@ScopeExtensions({DerivationType.APP_MSG_LENGHT, DerivationType.PADDING_BITMASK})
@ValueConstraints(affectedTypes = {DerivationType.CIPHERSUITE}, methods = "isCBC")
@DynamicValueConstraints(affectedTypes = DerivationType.RECORD_LENGTH, methods = "recordLengthAllowsModification")
@SecurityCategory(SeverityLevel.HIGH)
@CryptoCategory(SeverityLevel.CRITICAL)
@RecordLayerCategory(SeverityLevel.CRITICAL)
@AlertCategory(SeverityLevel.HIGH)
@ComplianceCategory(SeverityLevel.HIGH)
public void invalidCBCPadding(ArgumentsAccessor argumentAccessor, WorkflowRunner runner) {
    Config c = getPreparedConfig(argumentAccessor, runner);

    ApplicationMessage appData = new ApplicationMessage();
    appData.setData(Modifiable.explicit(c.getDefaultApplicationMessageData().getBytes()));

    byte[] modificationBitmask = derivationContainer.buildBitmask();

    Record record = new Record();
    record.setComputations(new RecordCryptoComputations());
    record.getComputations().setPadding(Modifiable.xor(modificationBitmask, 0));

    SendAction sendAction = new SendAction(appData);
    sendAction.setRecords(record);

    WorkflowTrace workflowTrace = runner.generateWorkflowTrace(WorkflowTraceType.HANDSHAKE);
    workflowTrace.addTlsActions(
            sendAction,
            new ReceiveAction(new AlertMessage())
    );

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
