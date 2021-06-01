package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerPackage;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerSpecification;

import de.uka.ipd.sdq.workflow.mdsd.blackboard.ResourceSetPartition;

public class AttackPartition extends ResourceSetPartition {

    public AttackerSpecification getAttackSpecification() {
        // FIXME solve Problem of not finding ContextContainer

        return (AttackerSpecification) this.getElement(AttackerPackage.eINSTANCE.getAttackerSpecification()).get(0);
        // return (ContextContainer)
    }
}
