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

import java.util.*;

public class ParameterExtensionManager {
    private static ParameterExtensionManager instance = null;
    private Map<String, ParameterExtension> availableExtensions;
    private Set<String> loadedExtensions;

    public static synchronized ParameterExtensionManager getInstance() {
        if (ParameterExtensionManager.instance == null) {
            ParameterExtensionManager.instance = new ParameterExtensionManager();
        }
        return ParameterExtensionManager.instance;
    }

    private ParameterExtensionManager(){
        availableExtensions = new HashMap<>();
        loadedExtensions = new HashSet<>();
        // Register new parameterExtensions here:
        //registerParameterExtension(TODO: Add ConfigOptionsExtension here);
    }

    public synchronized void registerParameterExtension(ParameterExtension parameterExtension) {
        if(availableExtensions.containsKey(parameterExtension.getIdentifier())){
            if(parameterExtension != availableExtensions.get(parameterExtension.getIdentifier()))
            throw new IllegalArgumentException(String.format("Tried to register Parameter Extension identifier '%s' twice with different Extension instances.", parameterExtension.getIdentifier()));
        }
        availableExtensions.put(parameterExtension.getIdentifier(), parameterExtension);
    }

    public Set<String> getAvailableExtensions(){
        return new HashSet<>(availableExtensions.keySet());
    }

    public Set<String> getLoadedExtensions(){
        return new HashSet<>(loadedExtensions);
    }

    public synchronized void loadExtension(String identifier){
        if(!availableExtensions.containsKey(identifier)){
            throw new IllegalArgumentException(String.format("Parameter Extension identifier '%s' is not known by the ParameterExtensionManager. Have you registered it?",identifier));
        }
        if(!loadedExtensions.contains(identifier)){
            availableExtensions.get(identifier).load();
            loadedExtensions.add(identifier);
        }
    }

    public synchronized void unloadExtension(String identifier){
        if(!availableExtensions.containsKey(identifier)){
            throw new IllegalArgumentException(String.format("Parameter Extension identifier '%s' is not known by the ParameterExtensionManager. Have you registered it?",identifier));
        }
        if(loadedExtensions.contains(identifier)){
            availableExtensions.get(identifier).unload();
            loadedExtensions.remove(identifier);
        }
    }


}
