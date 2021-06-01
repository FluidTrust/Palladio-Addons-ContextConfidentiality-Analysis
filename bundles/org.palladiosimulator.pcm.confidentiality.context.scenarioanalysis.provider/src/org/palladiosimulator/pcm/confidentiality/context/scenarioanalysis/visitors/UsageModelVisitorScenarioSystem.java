package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.visitors;

import java.util.HashSet;
import java.util.Set;

import org.palladiosimulator.pcm.usagemodel.EntryLevelSystemCall;

public class UsageModelVisitorScenarioSystem extends AbstractUsageModelVisitor<EntryLevelSystemCall> {

    @Override
    public Set<EntryLevelSystemCall> caseEntryLevelSystemCall(final EntryLevelSystemCall call) {
        final var list = new HashSet<EntryLevelSystemCall>();
        list.add(call);
        list.addAll(this.doSwitch(call.getSuccessor()));
        return list;
    }

}
