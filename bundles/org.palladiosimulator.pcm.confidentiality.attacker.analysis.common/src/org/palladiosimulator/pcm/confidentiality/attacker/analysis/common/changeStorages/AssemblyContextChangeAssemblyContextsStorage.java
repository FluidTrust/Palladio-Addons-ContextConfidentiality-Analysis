package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages;

import java.util.List;

import org.palladiosimulator.pcm.core.composition.AssemblyContext;

public class AssemblyContextChangeAssemblyContextsStorage extends ModelRelationCache<List<AssemblyContext>> {


    private static volatile AssemblyContextChangeAssemblyContextsStorage singleton;

    private static final Object object = new Object();


    private AssemblyContextChangeAssemblyContextsStorage() {
    }

    public static AssemblyContextChangeAssemblyContextsStorage getInstance() {

        if (singleton == null) {
            synchronized (object) {
                if (singleton == null) {
                    singleton = new AssemblyContextChangeAssemblyContextsStorage();
                }
            }

        }

        return singleton;
    }
}
