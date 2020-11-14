package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.emf.common.util.EList;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.helpers.PCMHelpers;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.BasicComponent;
import org.palladiosimulator.pcm.repository.Signature;
import org.palladiosimulator.pcm.seff.ServiceEffectSpecification;
import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;
import org.palladiosimulator.solver.transformations.PCMInstanceHelper;

public class UsageModelVisitorScenarioSystem extends AbstractUsageModelVisitor<EntryLevelSystemCall>{
   
    @Override
    public Set<EntryLevelSystemCall> caseEntryLevelSystemCall(EntryLevelSystemCall call) {
        var list = new HashSet<EntryLevelSystemCall>();
        list.add(call);
        list.addAll(doSwitch(call.getSuccessor()));
        return list;
    }


}
