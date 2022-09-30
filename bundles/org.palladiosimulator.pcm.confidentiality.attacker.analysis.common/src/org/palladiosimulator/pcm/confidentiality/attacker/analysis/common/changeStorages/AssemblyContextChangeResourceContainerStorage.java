package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages;

import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

public class AssemblyContextChangeResourceContainerStorage extends ModelRelationCache<ResourceContainer> {
    private static final Object object = new Object();

    private static volatile AssemblyContextChangeResourceContainerStorage singleton;


    private AssemblyContextChangeResourceContainerStorage() {
    }

    public static synchronized AssemblyContextChangeResourceContainerStorage getInstance() {
        if (singleton == null) {
            synchronized (object) {
                if (singleton == null) {
                    singleton = new AssemblyContextChangeResourceContainerStorage();
                }
            }

        }

        return singleton;
    }


}
