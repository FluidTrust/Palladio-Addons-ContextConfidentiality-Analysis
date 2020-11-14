package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.HashSet;
import java.util.Set;

import org.palladiosimulator.pcm.seff.ExternalCallAction;

public class SeffAssemblyContext extends AbstractSeffVisitor<ExternalCallAction>{
    
    @Override
    public Set<ExternalCallAction> caseExternalCallAction(ExternalCallAction action){
        var set = new HashSet<ExternalCallAction>();
        set.add(action);
        set.addAll(doSwitch(action.getSuccessor_AbstractAction()));
        return set;
    }
}
