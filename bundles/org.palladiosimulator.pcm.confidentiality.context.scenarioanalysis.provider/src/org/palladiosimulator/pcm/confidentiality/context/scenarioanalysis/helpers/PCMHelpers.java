package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.helpers;

import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;

public class PCMHelpers {
    private PCMHelpers() {
        assert false;
    }

    public static org.palladiosimulator.pcm.system.System getSystem(final EntryLevelSystemCall call) {
        return (org.palladiosimulator.pcm.system.System) call.getProvidedRole_EntryLevelSystemCall().eContainer();
    }
}
