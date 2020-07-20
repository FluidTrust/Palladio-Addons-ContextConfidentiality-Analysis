package org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.delegate;

import org.eclipse.core.runtime.CoreException;
import org.eclipse.debug.core.ILaunch;
import org.eclipse.debug.core.ILaunchConfiguration;
import org.eclipse.emf.common.util.URI;
import org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.workflow.AttackerAnalysisWorkflow;
import org.palladiosimulator.pcm.confidentiality.context.attackanalysis.execution.workflow.config.ContextAnalysisWorkflowConfig;

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
public class LaunchDelegate
        extends AbstractWorkflowBasedMDSDLaunchConfigurationDelegate<ContextAnalysisWorkflowConfig> {

    @Override
    protected ContextAnalysisWorkflowConfig deriveConfiguration(ILaunchConfiguration configuration, String mode)
            throws CoreException {
        var config = new ContextAnalysisWorkflowConfig();
        var builder = new AttackerAnalysisConfigurationBuilder(configuration, mode);
        builder.fillConfiguration(config);
        return config;
    }

    @Override
    protected IJob createWorkflowJob(ContextAnalysisWorkflowConfig config, ILaunch launch) throws CoreException {
        return new AttackerAnalysisWorkflow(config);
    }

}
