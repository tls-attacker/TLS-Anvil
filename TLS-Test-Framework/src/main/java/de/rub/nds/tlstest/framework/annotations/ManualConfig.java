package de.rub.nds.tlstest.framework.annotations;

import de.rub.nds.tlstest.framework.model.DerivationType;

/**
 * Sets DerivationTypes for which the chosen value should not be applied
 * to the config.
 */
public @interface ManualConfig {
    DerivationType[] value();
}
