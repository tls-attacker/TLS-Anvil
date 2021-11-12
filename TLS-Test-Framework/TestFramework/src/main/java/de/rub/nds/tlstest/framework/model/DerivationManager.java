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

import de.rub.nds.tlstest.framework.model.derivationParameter.BasicDerivationManager;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The manager that knows and manages all DerivationCategoryManager%s. It is used to collect the set of DerivationParameter%s
 * for a specified ModelType and ModelScope. Also it can used as a factory to create DerivationParameter%s for given DerivationType%s.
 *
 * The DerivationManager is a global Singleton.
 */
public class DerivationManager {
    private static DerivationManager instance = null;
    private static final Logger LOGGER = LogManager.getLogger();

    private Map<Class, DerivationCategoryManager> categoryManagers;

    public static DerivationManager getInstance() {
        if (DerivationManager.instance == null) {
            DerivationManager.instance = new DerivationManager();
        }
        return DerivationManager.instance;
    }

    private DerivationManager() {

    }

    public DerivationParameter getDerivationParameterInstance(DerivationType type) {
        // TODO
        return null;
    }

    public List<DerivationType> getDerivationsOfModel(DerivationScope derivationScope, ModelType baseModel) {
        // TODO
        return null;
    }

    public boolean registerCategoryManager(Class derivationTypeCategory, DerivationCategoryManager categoryManager){
        // TODO
        return false;
    }

    public boolean unregisterCategoryManager(Class derivationTypeCategory){
        // TODO
        return false;
    }

    public List<DerivationCategoryManager> getRegisteredCategoryManagers(){
        return new ArrayList<DerivationCategoryManager>(categoryManagers.values());
    }
}
