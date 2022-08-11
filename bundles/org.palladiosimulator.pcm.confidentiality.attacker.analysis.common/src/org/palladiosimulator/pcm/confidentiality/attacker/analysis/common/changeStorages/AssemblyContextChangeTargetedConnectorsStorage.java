package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages;

import java.util.HashMap;
import java.util.List;

import org.palladiosimulator.pcm.core.composition.AssemblyConnector;

public class AssemblyContextChangeTargetedConnectorsStorage {

    private static AssemblyContextChangeTargetedConnectorsStorage singleton;

    private HashMap<String, List<AssemblyConnector>> targetedConnectorsMap;

    private AssemblyContextChangeTargetedConnectorsStorage() {
        targetedConnectorsMap = new HashMap<>();
    }

    public static synchronized AssemblyContextChangeTargetedConnectorsStorage getInstance() {
        if (singleton == null) {
            singleton = new AssemblyContextChangeTargetedConnectorsStorage();
        }

        return singleton;
    }

    public void reset() {
        targetedConnectorsMap = new HashMap<>();
        targetedConnectorsMap.clear();
    }

    // IMPORTANT: HashMap is unsynchronized, so synchronization must be done here.
    public synchronized void put(String key, List<AssemblyConnector> value) {
        targetedConnectorsMap.put(key, value);
    }

    public List<AssemblyConnector> get(String key) {
        return targetedConnectorsMap.get(key);
    }

    public boolean contains(String key) {
        return targetedConnectorsMap.containsKey(key);
    }
}
