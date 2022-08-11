package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changeStorages;

import java.util.HashMap;

import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

public class AssemblyContextChangeResourceContainerStorage {

    private static AssemblyContextChangeResourceContainerStorage singleton;

    private HashMap<String, ResourceContainer> resourceContainerMap;

    private AssemblyContextChangeResourceContainerStorage() {
        resourceContainerMap = new HashMap<>();
    }

    public static synchronized AssemblyContextChangeResourceContainerStorage getInstance() {
        if (singleton == null) {
            singleton = new AssemblyContextChangeResourceContainerStorage();
        }

        return singleton;
    }

    public void reset() {
        resourceContainerMap = new HashMap<>();
        resourceContainerMap.clear();
    }

    // IMPORTANT: HashMap is unsynchronized, so synchronization must be done here.
    public synchronized void put(String key, ResourceContainer value) {
        resourceContainerMap.put(key, value);
    }

    public ResourceContainer get(String key) {
        return resourceContainerMap.get(key);
    }

    public boolean contains(String key) {
        return resourceContainerMap.containsKey(key);
    }
}
