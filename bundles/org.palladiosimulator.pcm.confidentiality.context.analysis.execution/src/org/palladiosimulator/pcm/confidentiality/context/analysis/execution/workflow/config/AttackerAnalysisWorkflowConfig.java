package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config;

import org.eclipse.emf.common.util.URI;

public class AttackerAnalysisWorkflowConfig extends ContextAnalysisWorkflowConfig {
    private URI dataModel;
    private URI attackModel;
    private URI modificationModel;
    private boolean generateGraph;

    public URI getDataModel() {
        return this.dataModel;
    }

    public void setDataModel(final URI dataModel) {
        this.dataModel = dataModel;
    }

    public URI getAttackModel() {
        return this.attackModel;
    }

    public void setAttackModel(final URI adversaryModel) {
        this.attackModel = adversaryModel;
    }

    public URI getModificationModel() {
        return this.modificationModel;
    }

    public void setModificationModel(final URI adversaryModel) {
        this.modificationModel = adversaryModel;
    }

    public void setGenerateGraph(boolean generateGraph) {
        this.generateGraph = generateGraph;
    }

    public boolean getGenerateGraph() {
        return this.generateGraph;
    }

}
