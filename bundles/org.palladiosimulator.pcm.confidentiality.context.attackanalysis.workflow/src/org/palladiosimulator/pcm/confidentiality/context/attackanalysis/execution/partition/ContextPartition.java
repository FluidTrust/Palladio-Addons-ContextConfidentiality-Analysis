package org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.partition;

import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.ContextPackage;

import de.uka.ipd.sdq.workflow.mdsd.blackboard.ResourceSetPartition;

public class ContextPartition extends ResourceSetPartition{
    public ConfidentialAccessSpecification getContextSpecification() {
        //FIXME solve Problem of not finding ContextContainer
        return (ConfidentialAccessSpecification) getElement(ContextPackage.eINSTANCE.getConfidentialAccessSpecification());
        //return (ContextContainer) 
    }
}
