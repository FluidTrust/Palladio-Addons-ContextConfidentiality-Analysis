package org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.delegate;

import org.eclipse.core.runtime.CoreException;
import org.eclipse.debug.core.ILaunch;
import org.eclipse.debug.core.ILaunchConfiguration;
import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow.VariationWorkFlowNoBoard;
import org.palladiosimulator.pcm.confidentiality.attacker.variation.workflow.VariationWorkflowConfig;
import org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.constants.Constants;

import de.uka.ipd.sdq.workflow.jobs.IJob;
import de.uka.ipd.sdq.workflow.mdsd.AbstractWorkflowBasedMDSDLaunchConfigurationDelegate;

/**
 * Launches a given launch configuration with an usage model,an allocation model and a
 * characteristics model.
 *
 * @author majuwa
 * @author Mirko Sowa
 *
 */
public class LaunchDelegateVariations
        extends AbstractWorkflowBasedMDSDLaunchConfigurationDelegate<VariationWorkflowConfig> {

    @Override
    protected VariationWorkflowConfig deriveConfiguration(final ILaunchConfiguration configuration,
            final String mode) throws CoreException {
        final var output = configuration.getAttribute(Constants.VARIATION_MODEL_LABEL, "default");
        var config = new VariationWorkflowConfig();
        config.setVariationModel(URI.createURI(output));
        return config;

    }

    @Override
    protected IJob createWorkflowJob(final VariationWorkflowConfig config, final ILaunch launch)
            throws CoreException {
        return new VariationWorkFlowNoBoard(config);
    }

}
