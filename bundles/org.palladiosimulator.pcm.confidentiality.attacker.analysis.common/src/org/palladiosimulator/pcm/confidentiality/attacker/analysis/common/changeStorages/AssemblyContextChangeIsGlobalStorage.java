package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages;

import java.util.HashMap;

public class AssemblyContextChangeIsGlobalStorage {

    private static AssemblyContextChangeIsGlobalStorage singleton;

    private HashMap<String, Boolean> isAssemblyContextGlobalMap;

    private AssemblyContextChangeIsGlobalStorage() {
        isAssemblyContextGlobalMap = new HashMap<>();
    }

    public static synchronized AssemblyContextChangeIsGlobalStorage getInstance() {
        if (singleton == null) {
            singleton = new AssemblyContextChangeIsGlobalStorage();
        }

        return singleton;
    }

    public void reset() {
        isAssemblyContextGlobalMap = new HashMap<>();
        isAssemblyContextGlobalMap.clear();
    }

    // IMPORTANT: HashMap is unsynchronized, so synchronization must be done here.
    public synchronized void put(String key, Boolean value) {
        isAssemblyContextGlobalMap.put(key, value);
    }

    public Boolean get(String key) {
        return isAssemblyContextGlobalMap.get(key);
    }

    public boolean contains(String key) {
        return isAssemblyContextGlobalMap.containsKey(key);
    }

}
