package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages;

import java.util.List;

import org.palladiosimulator.pcm.core.composition.AssemblyContext;

public class ResourceContainerChangeAssemblyContextsStorage extends ModelRelationCache<List<AssemblyContext>> {
    private static final Object object = new Object();

    private static volatile ResourceContainerChangeAssemblyContextsStorage singleton;

    private ResourceContainerChangeAssemblyContextsStorage() {
    }

    public static synchronized ResourceContainerChangeAssemblyContextsStorage getInstance() {
        if (singleton == null) {
            synchronized (object) {
                if (singleton == null) {
                    singleton = new ResourceContainerChangeAssemblyContextsStorage();
                }
            }

        }

        return singleton;
    }

}
