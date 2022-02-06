package edu.kit.ipd.sdq.attacksurface.core;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;

public final class CauseFinderHelper {
    private CauseFinderHelper() {
        
    }
    
    public static List<String> findContentIdsOfCauses(final List<SystemIntegration> relevantSytemIntegrations) {
        return relevantSytemIntegrations.stream()
                    .map(SystemIntegration::getIdOfContent)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());
    }
}
