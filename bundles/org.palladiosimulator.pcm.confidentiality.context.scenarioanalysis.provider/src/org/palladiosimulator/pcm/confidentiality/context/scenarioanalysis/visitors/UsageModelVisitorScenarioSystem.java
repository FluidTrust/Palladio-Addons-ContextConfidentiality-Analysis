package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.HashSet;
import java.util.Set;

import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;


public class UsageModelVisitorScenarioSystem extends AbstractUsageModelVisitor<EntryLevelSystemCall>{
   
    @Override
    public Set<EntryLevelSystemCall> caseEntryLevelSystemCall(EntryLevelSystemCall call) {
        var list = new HashSet<EntryLevelSystemCall>();
        list.add(call);
        list.addAll(doSwitch(call.getSuccessor()));
        return list;
    }


}
