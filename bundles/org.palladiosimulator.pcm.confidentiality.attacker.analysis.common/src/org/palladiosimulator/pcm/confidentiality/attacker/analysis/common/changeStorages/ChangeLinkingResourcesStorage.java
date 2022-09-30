package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.changeStorages;

import java.util.List;

import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;

public class ChangeLinkingResourcesStorage extends ModelRelationCache<List<LinkingResource>> {

    private static final Object object = new Object();

    private static volatile ChangeLinkingResourcesStorage singleton;


    private ChangeLinkingResourcesStorage() {
    }

    public static synchronized ChangeLinkingResourcesStorage getInstance() {
        if (singleton == null) {
            synchronized (object) {
                if (singleton == null) {
                    singleton = new ChangeLinkingResourcesStorage();
                }
            }

        }

        return singleton;
    }



}
