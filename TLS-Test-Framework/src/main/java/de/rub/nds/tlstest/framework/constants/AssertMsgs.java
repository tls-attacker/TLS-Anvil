/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.constants;

public class AssertMsgs {
    public static final String WorkflowNotExecutedBeforeAlert =
            "The workflow execution failed before reaching the expected alert!";
    public static final String WorkflowNotExecuted =
            "The workflow could not be executed as planned!";
    public static final String ClientHelloNotReceived = "ClientHello not received!";
    public static final String ServerHelloNotReceived = "ServerHello not received!";
    public static final String ServerKxNotReceived = "ServerKeyExchange not received!";
    public static final String ServerHelloDoneNotReceived = "ServerHelloDone not received!";
    public static final String EncExtensionsNotReceived = "EncryptedExtensions not received!";
    public static final String ClientKxNotReceived = "ClientKx not received!";
    public static final String FinishedNotReceived = "Finished not received!";
    public static final String AlertNotReceived = "Alert not received!";
    public static final String NoFatalAlert = "No fatal alert received!";
    public static final String NoWarningAlert = "No warning alert received!";
    public static final String UnexpectedCipherSuite = "Received unexpected ciphersuite!";
    public static final String UnexpectedAlertDescription = "Received unexpected alert description";
}
