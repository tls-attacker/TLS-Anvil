/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * Copyright 2020 Ruhr University Bochum and
 * TÜV Informationstechnik GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model;

/**
 *
 * Represents the properties affected by the test derivation models.
 */
public enum DerivationType {
    CIPHERSUITE,
    NAMED_GROUP,
    MAC_BITMASK,
    ALERT,
    RECORD_LENGTH,
    TCP_FRAGMENTATION,
    CIPHERTEXT_BITMASK,
    AUTH_TAG_BITMASK,
    APP_MSG_LENGHT,
    PADDING_BITMASK,
    INVALID_CCS_CONTENT,
    PRF_BITMASK,
    GREASE_CIPHERSUITE,
    GREASE_PROTOCOL_VERSION,
    GREASE_EXTENSION,
    GREASE_NAMED_GROUP,
    GREASE_SIG_HASH,
    PROTOCOL_VERSION,
    SIG_HASH_ALGORIHTM,
    EXTENSION,
    CHOSEN_HANDSHAKE_MSG,
    BIT_POSITION;
    
    public boolean isBitmaskDerivation() {
        return this.name().contains("BITMASK");
    }
}
