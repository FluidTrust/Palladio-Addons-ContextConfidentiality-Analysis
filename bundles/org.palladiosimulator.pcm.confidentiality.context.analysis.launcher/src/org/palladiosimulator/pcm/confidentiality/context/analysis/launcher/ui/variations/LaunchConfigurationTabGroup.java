
package org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.ui.variations;

import org.eclipse.debug.ui.AbstractLaunchConfigurationTabGroup;
import org.eclipse.debug.ui.CommonTab;
import org.eclipse.debug.ui.ILaunchConfigurationDialog;

/**
 * Parent Group of the tab configuration.
 *
 * @author Mirko Sowa
 *
 */
public class LaunchConfigurationTabGroup extends AbstractLaunchConfigurationTabGroup {

    /**
     * Opens to tabs, {@link VariationInputTab} (the main tab) and a {@link TranslatorSettingsTab}
     */
    @Override
    public void createTabs(final ILaunchConfigurationDialog dialog, final String mode) {
        setTabs(new VariationInputTab(), new CommonTab());
    }

}
