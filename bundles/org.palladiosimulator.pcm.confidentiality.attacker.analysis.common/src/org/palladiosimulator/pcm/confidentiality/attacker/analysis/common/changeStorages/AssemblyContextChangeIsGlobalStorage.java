package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages;

public class AssemblyContextChangeIsGlobalStorage extends ModelRelationCache<Boolean> {
    private static final Object object = new Object();

    private static volatile AssemblyContextChangeIsGlobalStorage singleton;

    private AssemblyContextChangeIsGlobalStorage() {

    }

    public static synchronized AssemblyContextChangeIsGlobalStorage getInstance() {
        if (singleton == null) {
            synchronized (object) {
                if (singleton == null) {
                    singleton = new AssemblyContextChangeIsGlobalStorage();
                }
            }

        }

        return singleton;
    }

}
