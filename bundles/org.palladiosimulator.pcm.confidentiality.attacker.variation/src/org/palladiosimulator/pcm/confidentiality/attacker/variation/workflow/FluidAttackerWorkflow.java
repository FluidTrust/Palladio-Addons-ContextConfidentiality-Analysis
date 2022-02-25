package org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow;

import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_MODIFICATION;

import java.util.ArrayList;
import java.util.List;

import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.AttackerAnalysisWorkflow;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.AttackerAnalysisWorkflowConfig;

import de.uka.ipd.sdq.workflow.jobs.IJob;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.SavePartitionToDiskJob;

public class FluidAttackerWorkflow extends AttackerAnalysisWorkflow {

    public FluidAttackerWorkflow(final AttackerAnalysisWorkflowConfig config) {
        super(config);
    }

    @Override
    protected List<IJob> getOutputJob() {
        final var outputJobs = new ArrayList<IJob>();
        outputJobs.add(new DeSerializeJob());
        outputJobs.add(new SavePartitionToDiskJob(PARTITION_ID_MODIFICATION));
        return outputJobs;
    }

}
