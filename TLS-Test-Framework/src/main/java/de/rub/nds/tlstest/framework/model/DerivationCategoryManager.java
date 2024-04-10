/**
 * TLS-Test-Framework - A framework for modeling TLS tests
 *
 * <p>Copyright 2020 Ruhr University Bochum and TÜV Informationstechnik GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlstest.framework.model;

import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import java.util.List;

/**
 * Interface for the managers that manages a certain derivation type. These managers implement the
 * functionality of a DerivationParameter factory. Also the manager assign the derivation parameters
 * based on the DerivationScope and the used ModelType.
 */
public interface DerivationCategoryManager {
    DerivationParameter getDerivationParameterInstance(DerivationType type);

    List<DerivationType> getDerivationsOfModel(
            DerivationScope derivationScope, ModelType baseModel);

    List<DerivationType> getAllDerivations();
}
