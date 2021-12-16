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

import de.rub.nds.tlstest.framework.parameterExtensions.configurationOptionsExtension.ConfigurationOptionsExtension;

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
        registerParameterExtension(ConfigurationOptionsExtension.getInstance());

        // Ensure that all extensions are unloaded properly, even if stopped using CTRL+C
        Thread unloadAllHook = new Thread(() -> this.unloadAllExtensions());
        Runtime.getRuntime().addShutdownHook(unloadAllHook);
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

    /**
     * Loads the extension identified by the specified identifier.
     *
     * @param identifier - The identifier of the extension to load
     * @param initData - Some data to initialize the extension. The expected data and type depends on the extension.
     */
    public synchronized void loadExtension(String identifier, Object initData){
        if(!availableExtensions.containsKey(identifier)){
            throw new IllegalArgumentException(String.format("Parameter Extension identifier '%s' is not known by the ParameterExtensionManager. Have you registered it?",identifier));
        }
        if(!loadedExtensions.contains(identifier)){
            availableExtensions.get(identifier).load(initData);
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

    public synchronized  void unloadAllExtensions(){
        for(String identifier : loadedExtensions){
            unloadExtension(identifier);
        }
    }


}
