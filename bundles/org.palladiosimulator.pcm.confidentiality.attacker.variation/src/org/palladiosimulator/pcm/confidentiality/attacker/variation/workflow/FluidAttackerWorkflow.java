package org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow;

import java.util.ArrayList;
import java.util.List;

import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.AttackerAnalysisWorkflow;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.AttackerAnalysisWorkflowConfig;

import de.uka.ipd.sdq.workflow.jobs.IJob;

public class FluidAttackerWorkflow extends AttackerAnalysisWorkflow {


    public FluidAttackerWorkflow(AttackerAnalysisWorkflowConfig config) {
        super(config);
    }

    @Override
    protected List<IJob> getOutputJob() {
        var outputJobs = new ArrayList<IJob>();
        outputJobs.add(new DeSerializeJob());
        return outputJobs;
    }

}
