/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2022 Ruhr University Bochum
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.constants;

public class AssertMsgs {
    public static final String WORKFLOW_NOT_EXECUTED_BEFORE_ALERT =
            "The workflow execution failed before reaching the expected alert!";
    public static final String WORKFLOW_NOT_EXECUTED =
            "The workflow could not be executed as planned!";
    public static final String CLIENT_HELLO_NOT_RECEIVED = "ClientHello not received!";
    public static final String SERVER_HELLO_NOT_RECEIVED = "ServerHello not received!";
    public static final String SERVER_KEY_EXCHANGE_NOT_RECEIVED = "ServerKeyExchange not received!";
    public static final String SERVER_HELLO_DONE_NOT_RECEIVED = "ServerHelloDone not received!";
    public static final String ENCRYPTED_EXTENSIONS_NOT_RECEIVED =
            "EncryptedExtensions not received!";
    public static final String CLIENT_KEY_EXCHANGE_NOT_RECEIVED = "ClientKx not received!";
    public static final String FINISHED_NOT_RECEIVED = "Finished not received!";
    public static final String ALERT_NOT_RECEIVED = "Alert not received!";
    public static final String NO_FATAL_ALERT = "No fatal alert received!";
    public static final String NO_WARNING_ALERT = "No warning alert received!";
    public static final String UNEXPECTED_CIPHER_SUITE = "Received unexpected ciphersuite!";
    public static final String UNEXPECTED_ALERT_DESCRIPTION =
            "Received unexpected alert description";
}
