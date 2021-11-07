/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.constants;

public class AssertMsgs {
    public final static String WorkflowNotExecutedBeforeAlert = "The workflow execution failed before reaching the expected alert!";
    public final static String WorkflowNotExecuted = "The workflow could not be executed as planned!";
    public final static String ClientHelloNotReceived = "ClientHello not received!";
    public final static String ServerHelloNotReceived = "ServerHello not received!";
    public final static String ServerKxNotReceived = "ServerKeyExchange not received!";
    public final static String ServerHelloDoneNotReceived = "ServerHelloDone not received!";
    public final static String EncExtensionsNotReceived = "EncryptedExtensions not received!";
    public final static String ClientKxNotReceived = "ClientKx not received!";
    public final static String FinishedNotReceived = "Finished not received!";
    public final static String AlertNotReceived = "Alert not received!";
    public final static String NoFatalAlert = "No fatal alert received!";
    public final static String NoWarningAlert = "No warning alert received!";
    public final static String UnexpectedCipherSuite = "Received unexpected ciphersuite!";
    public final static String UnexpectedAlertDescription = "Received unexpected alert description";
}
