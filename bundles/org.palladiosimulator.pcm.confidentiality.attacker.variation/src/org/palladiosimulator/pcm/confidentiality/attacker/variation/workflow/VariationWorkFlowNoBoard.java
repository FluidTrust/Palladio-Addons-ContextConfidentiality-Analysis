package org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow;

import org.palladiosimulator.dataflow.confidentiality.transformation.workflow.blackboards.KeyValueMDSDBlackboard;

import de.uka.ipd.sdq.workflow.jobs.SequentialJob;

public class VariationWorkFlowNoBoard extends SequentialJob {

    public VariationWorkFlowNoBoard(VariationWorkflowConfig config) {

        var job = new VariationWorkflow(config);
        job.setBlackboard(new KeyValueMDSDBlackboard());
        addJob(job);
    }
}
