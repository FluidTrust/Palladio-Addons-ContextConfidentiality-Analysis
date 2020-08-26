package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config;

import org.eclipse.emf.common.util.URI;

public class AttackerAnalyisWorkflowConfig extends ContextAnalysisWorkflowConfig {
    private URI dataModel;
    private URI adversaryModel;
    
    public URI getDataModel() {
        return dataModel;
    }

    public void setDataModel(URI dataModel) {
        this.dataModel = dataModel;
    }

    public URI getAdversaryModel() {
        return adversaryModel;
    }

    public void setAdversaryModel(URI adversaryModel) {
        this.adversaryModel = adversaryModel;
    }

}
