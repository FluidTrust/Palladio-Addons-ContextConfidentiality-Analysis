/**
 *
 */
package org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config;

import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.AttackerAnalysisWorkflow;

import de.uka.ipd.sdq.workflow.launchconfig.AbstractWorkflowBasedRunConfiguration;

/**
 * This class encapsulates most of the attributes needed for an {@link AttackerAnalysisWorkflow}.
 *
 *
 *
 */
public abstract class ContextAnalysisWorkflowConfig extends AbstractWorkflowBasedRunConfiguration {

    private URI repositoryModel;
    private URI allocationModel;
    private URI contextModel;
    private URI outputXACML;

    public URI getRepositoryModel() {
        return this.repositoryModel;
    }

    public void setRepositoryModel(final URI repositoryModel) {
        this.repositoryModel = repositoryModel;
    }

    public URI getAllocationModel() {
        return this.allocationModel;
    }

    public void setAllocationModel(final URI allocationModel) {
        this.allocationModel = allocationModel;
    }

    public URI getContextModel() {
        return this.contextModel;
    }

    public void setContextModel(final URI contextModel) {
        this.contextModel = contextModel;
    }

    public URI getOutputXACML() {
        return this.outputXACML;
    }

    public void setOutputXACML(URI outputXACML) {
        this.outputXACML = outputXACML;
    }

    @Override
    public String getErrorMessage() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void setDefaults() {
        // TODO Auto-generated method stub

    }

}
