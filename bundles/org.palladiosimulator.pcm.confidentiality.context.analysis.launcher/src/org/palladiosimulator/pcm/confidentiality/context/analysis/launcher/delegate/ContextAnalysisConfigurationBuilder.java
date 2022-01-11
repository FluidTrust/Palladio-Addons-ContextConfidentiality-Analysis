package org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.delegate;

import org.eclipse.core.runtime.CoreException;
import org.eclipse.debug.core.ILaunchConfiguration;
import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.pcm.confidentiality.context.analysis.execution.workflow.config.ContextAnalysisWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.constants.Constants;

import de.uka.ipd.sdq.workflow.launchconfig.AbstractWorkflowBasedRunConfiguration;
import de.uka.ipd.sdq.workflow.launchconfig.AbstractWorkflowConfigurationBuilder;

/**
 * This class can build an Attacker analysis specific configuration objects out of a given Eclipse
 * Launch Configuration.
 *
 * @author majuwa
 *
 */
public abstract class ContextAnalysisConfigurationBuilder extends AbstractWorkflowConfigurationBuilder {

    protected ContextAnalysisConfigurationBuilder(final ILaunchConfiguration configuration, final String mode)
            throws CoreException {
        super(configuration, mode);
    }

    @Override
    public void fillConfiguration(final AbstractWorkflowBasedRunConfiguration configuration) throws CoreException {
        if (!(configuration instanceof ContextAnalysisWorkflowConfig)) {
            throw new IllegalArgumentException("configuration is from type " + configuration.getClass() + ", but "
                    + ContextAnalysisWorkflowConfig.class + " expected");
        }
        final var config = (ContextAnalysisWorkflowConfig) configuration;
        config.setContextModel(getURI(Constants.CONTEXT_MODEL_LABEL));
        config.setRepositoryModel(getURI(Constants.REPOSITORY_MODEL_LABEL));
        config.setAllocationModel(getURI(Constants.ALLOCATION_MODEL_LABEL));

    }

    protected URI getURI(final String pathValue) throws CoreException {
        return URI.createURI(getStringAttribute(pathValue));
    }

}
