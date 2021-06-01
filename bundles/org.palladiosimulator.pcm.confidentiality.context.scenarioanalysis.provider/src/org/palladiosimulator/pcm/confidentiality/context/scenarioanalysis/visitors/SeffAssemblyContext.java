package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.HashSet;
import java.util.Set;

import org.palladiosimulator.pcm.seff.ExternalCallAction;

public class SeffAssemblyContext extends AbstractSeffVisitor<ExternalCallAction> {

    @Override
    public Set<ExternalCallAction> caseExternalCallAction(final ExternalCallAction action) {
        final var set = new HashSet<ExternalCallAction>();
        set.add(action);
        set.addAll(this.doSwitch(action.getSuccessor_AbstractAction()));
        return set;
    }
}
