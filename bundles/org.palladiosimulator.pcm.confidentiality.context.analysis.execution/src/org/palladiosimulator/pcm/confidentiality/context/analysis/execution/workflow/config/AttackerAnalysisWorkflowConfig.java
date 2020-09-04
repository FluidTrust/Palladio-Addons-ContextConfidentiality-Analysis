package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config;

import org.eclipse.emf.common.util.URI;

public class AttackerAnalysisWorkflowConfig extends ContextAnalysisWorkflowConfig {
    private URI dataModel;
    private URI adversaryModel;
    private URI modificationModel;

    public URI getDataModel() {
        return this.dataModel;
    }

    public void setDataModel(final URI dataModel) {
        this.dataModel = dataModel;
    }

    public URI getAdversaryModel() {
        return this.adversaryModel;
    }

    public void setAdversaryModel(final URI adversaryModel) {
        this.adversaryModel = adversaryModel;
    }
    
    public URI getModificationModel() {
        return this.modificationModel;
    }

    public void setModificationModel(final URI adversaryModel) {
        this.modificationModel = adversaryModel;
    }

}
