package org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow;

import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.VariationWorkflowConfig;
import org.palladiosimulator.pcm.uncertainty.variation.UncertaintyVariationModel.gen.pcm.workflow.UncertaintyWorkflowJob;

import de.uka.ipd.sdq.workflow.jobs.SequentialBlackboardInteractingJob;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.MDSDBlackboard;

public class VariationWorkflow extends SequentialBlackboardInteractingJob<MDSDBlackboard> {
    public VariationWorkflow(VariationWorkflowConfig config) {

        this.add(new UncertaintyWorkflowJob(config.getVariationModel()));
        this.add(new RunMultipleAttackAnalysesJob(config));
    }

}
