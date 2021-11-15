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
import de.rub.nds.tlstest.framework.model.derivationParameter.BasicDerivationType;
import de.rub.nds.tlstest.framework.model.derivationParameter.DerivationParameter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

/**
 * The manager that knows and manages all DerivationCategoryManager%s. It is used to collect the set of DerivationParameter%s
 * for a specified ModelType and ModelScope. Also it can used as a factory to create DerivationParameter%s for given DerivationType%s.
 *
 * The basic derivation type is registered by default.
 *
 * The DerivationManager is a global Singleton.
 */
public class DerivationManager {
    private static DerivationManager instance = null;
    private static final Logger LOGGER = LogManager.getLogger();

    private Map<Class, DerivationCategoryManager> categoryManagers;

    public static synchronized DerivationManager getInstance() {
        if (DerivationManager.instance == null) {
            DerivationManager.instance = new DerivationManager();
        }
        return DerivationManager.instance;
    }

    private DerivationManager() {
        categoryManagers = new HashMap<>();
        registerCategoryManager(BasicDerivationType.class, BasicDerivationManager.getInstance());
    }


    public synchronized DerivationParameter getDerivationParameterInstance(DerivationType type) {
        for (Map.Entry<Class, DerivationCategoryManager> entry : categoryManagers.entrySet()) {
            if(entry.getKey() == type.getClass()){
                return entry.getValue().getDerivationParameterInstance(type);
            }
        }
        LOGGER.error("Derivations of type category {} were not registered in the DerivationManager.", type);
        throw new UnsupportedOperationException("Derivation Type Category not registered");
    }

    public synchronized List<DerivationType> getDerivationsOfModel(DerivationScope derivationScope, ModelType baseModel) {
        List<DerivationType> derivationsOfModel = new LinkedList<>();
        for (Map.Entry<Class, DerivationCategoryManager> entry : categoryManagers.entrySet()) {
            derivationsOfModel.addAll(entry.getValue().getDerivationsOfModel(derivationScope, baseModel));
        }
        return derivationsOfModel;
    }

    public synchronized void registerCategoryManager(Class derivationTypeCategory, DerivationCategoryManager categoryManager){
        if(!DerivationType.class.isAssignableFrom(derivationTypeCategory)){
            throw new IllegalArgumentException(String.format("Passed derivationTypeCategory '%s' does not implement the DerivationType interface.", derivationTypeCategory.toString()));
        }
        categoryManagers.put(derivationTypeCategory, categoryManager);
    }

    public synchronized void unregisterCategoryManager(Class derivationTypeCategory){
        categoryManagers.remove(derivationTypeCategory);
    }

    public synchronized List<DerivationCategoryManager> getRegisteredCategoryManagers(){
        return new ArrayList<DerivationCategoryManager>(categoryManagers.values());
    }
}
