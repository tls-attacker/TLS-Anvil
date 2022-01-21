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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
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


    public DerivationParameter getDerivationParameterInstance(DerivationType type) {
        for (Map.Entry<Class, DerivationCategoryManager> entry : categoryManagers.entrySet()) {
            if(entry.getKey() == type.getClass()){
                return entry.getValue().getDerivationParameterInstance(type);
            }
        }
        LOGGER.error("Derivations of type category {} were not registered in the DerivationManager.", type);
        throw new UnsupportedOperationException("Derivation Type Category not registered");
    }

    public List<DerivationType> getDerivationsOfModel(DerivationScope derivationScope, ModelType baseModel) {
        List<DerivationType> derivationsOfModel = new LinkedList<>();
        for (Map.Entry<Class, DerivationCategoryManager> entry : categoryManagers.entrySet()) {
            derivationsOfModel.addAll(entry.getValue().getDerivationsOfModel(derivationScope, baseModel));
        }
        return derivationsOfModel;
    }

    public List<DerivationType> getAllDerivations(){
        List<DerivationType> allDerivations = new LinkedList<>();
        for (Map.Entry<Class, DerivationCategoryManager> entry : categoryManagers.entrySet()) {
            allDerivations.addAll(entry.getValue().getAllDerivations());
        }
        return allDerivations;
    }

    public DerivationType getDerivationFromString(String derivationString){
        String[] splittedString = derivationString.split("\\.");
        if(splittedString.length != 2){
            throw new IllegalArgumentException(String.format("Illegal String format. Derivation format is '<TypeEnum>.<TypeName>' but '%s' was given.", derivationString));
        }
        String derivationTypeEnum = splittedString[0];
        String derivationTypeName = splittedString[1];
        Class associatedClass = null;
        for (Map.Entry<Class, DerivationCategoryManager> entry : categoryManagers.entrySet()) {
            Class registeredTypeEnum = entry.getKey();
            String className = registeredTypeEnum.getSimpleName();
            if(derivationTypeEnum.equals(className)){
                associatedClass = registeredTypeEnum;
                break;
            }
        }
        if(associatedClass == null){
            List<String> registeredTypes = new LinkedList<>();
            for(Map.Entry<Class, DerivationCategoryManager> entry : categoryManagers.entrySet()){
                registeredTypes.add(entry.getKey().getSimpleName());
            }
            throw new UnsupportedOperationException(String.format("Derivations of type '%s' are not registered. Registered types are: %s", derivationTypeEnum, String.join(", ", registeredTypes)));
        }

        Method valueOfMethod;
        Object result;

        try{
            valueOfMethod = associatedClass.getMethod("valueOf", String.class);
            result = valueOfMethod.invoke(null, derivationTypeName);
        }
        catch (NoSuchMethodException e) {
            // Should never happen, because associatedClass is always an enum.
            e.printStackTrace();
            throw new RuntimeException(String.format("%s is no enum. This should not happen.", derivationTypeEnum));
        }
        catch (InvocationTargetException e) {
            if (e.getCause() instanceof IllegalArgumentException){
                throw new IllegalArgumentException(String.format("There is no value '%s' in enum %s.", derivationTypeName, derivationTypeEnum));
            }
            else{
                throw new RuntimeException(String.format("Unknown Exception was thrown.", derivationTypeEnum));
            }
        }
        catch (IllegalAccessException e) {
            e.printStackTrace();
            throw new RuntimeException(String.format("Cannot access %s.", derivationString));
        }

        DerivationType resultDerivationType = (DerivationType) result;

        return resultDerivationType;
    }

    public synchronized void registerCategoryManager(Class derivationTypeCategory, DerivationCategoryManager categoryManager){
        if(!DerivationType.class.isAssignableFrom(derivationTypeCategory)){
            throw new IllegalArgumentException(String.format("Passed derivationTypeCategory '%s' does not implement the DerivationType interface.", derivationTypeCategory.toString()));
        }
        if(!derivationTypeCategory.isEnum()){
            throw new IllegalArgumentException(String.format("Passed derivationTypeCategory '%s' is not an enum.", derivationTypeCategory.toString()));
        }
        categoryManagers.put(derivationTypeCategory, categoryManager);
    }

    public synchronized void unregisterCategoryManager(Class derivationTypeCategory){
        categoryManagers.remove(derivationTypeCategory);
    }

    public synchronized List<DerivationCategoryManager> getRegisteredCategoryManagers(){
        return new ArrayList<>(categoryManagers.values());
    }
}
