package org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow;

import org.palladiosimulator.dataflow.confidentiality.transformation.workflow.blackboards.KeyValueMDSDBlackboard;

import de.uka.ipd.sdq.workflow.jobs.SequentialJob;

public class VariationWorkFlowNoBoard extends SequentialJob {

    public VariationWorkFlowNoBoard(final VariationWorkflowConfig config) {

        final var job = new VariationWorkflow(config);
        job.setBlackboard(new KeyValueMDSDBlackboard());
        this.addJob(job);
    }
}
