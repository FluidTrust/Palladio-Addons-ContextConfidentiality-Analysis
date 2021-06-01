package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.Set;

import org.palladiosimulator.pcm.seff.ResourceDemandingBehaviour;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;

public class SeffVisitorScenarioAnalysis extends AbstractSeffVisitor<ResourceDemandingBehaviour> {

    @Override
    public Set<ResourceDemandingBehaviour> caseResourceDemandingSEFF(final ResourceDemandingSEFF behaviour) {
        final var set = super.caseResourceDemandingSEFF(behaviour);
        set.add(behaviour);
        return set;
    }
}
