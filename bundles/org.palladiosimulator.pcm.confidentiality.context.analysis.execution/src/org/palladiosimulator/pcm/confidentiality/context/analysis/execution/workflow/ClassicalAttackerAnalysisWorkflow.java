package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow;

import static org.palladiosimulator.pcm.confidentiality.context.analysis.execution.partition.PartitionConstants.PARTITION_ID_MODIFICATION;

import java.util.ArrayList;
import java.util.List;

import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ClassicalAttackerAnalysisWorkflowConfig;

import de.uka.ipd.sdq.workflow.jobs.IJob;
import de.uka.ipd.sdq.workflow.mdsd.blackboard.SavePartitionToDiskJob;

public class ClassicalAttackerAnalysisWorkflow extends AttackerAnalysisWorkflow {

    public ClassicalAttackerAnalysisWorkflow(ClassicalAttackerAnalysisWorkflowConfig config) {
        super(config);
    }

    @Override
    protected List<IJob> getOutputJob() {
        var jobList = new ArrayList<IJob>();
        jobList.add(new SavePartitionToDiskJob(PARTITION_ID_MODIFICATION));
        return jobList;
    }

}
