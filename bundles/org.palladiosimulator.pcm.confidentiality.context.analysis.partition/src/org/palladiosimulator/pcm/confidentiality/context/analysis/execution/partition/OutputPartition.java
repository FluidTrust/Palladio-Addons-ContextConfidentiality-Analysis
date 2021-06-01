package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition;

import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.AnalysisResults;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage;

import de.uka.ipd.sdq.workflow.mdsd.blackboard.ResourceSetPartition;

public class OutputPartition extends ResourceSetPartition {
    public AnalysisResults getAnalysisResults() {
        return (AnalysisResults) this.getElement(OutputmodelPackage.eINSTANCE.getAnalysisResults()).get(0);
    }
}
