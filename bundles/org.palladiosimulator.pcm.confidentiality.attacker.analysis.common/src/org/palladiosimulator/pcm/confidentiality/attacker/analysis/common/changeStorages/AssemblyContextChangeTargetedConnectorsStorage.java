package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages;

import java.util.List;

import org.palladiosimulator.pcm.core.composition.AssemblyConnector;

public class AssemblyContextChangeTargetedConnectorsStorage extends ModelRelationCache<List<AssemblyConnector>> {
    private static final Object object = new Object();

    private static volatile AssemblyContextChangeTargetedConnectorsStorage singleton;

    private AssemblyContextChangeTargetedConnectorsStorage() {
    }

    public static synchronized AssemblyContextChangeTargetedConnectorsStorage getInstance() {
        if (singleton == null) {
            synchronized (object) {
                if (singleton == null) {
                    singleton = new AssemblyContextChangeTargetedConnectorsStorage();
                }
            }

        }

        return singleton;
    }
}
