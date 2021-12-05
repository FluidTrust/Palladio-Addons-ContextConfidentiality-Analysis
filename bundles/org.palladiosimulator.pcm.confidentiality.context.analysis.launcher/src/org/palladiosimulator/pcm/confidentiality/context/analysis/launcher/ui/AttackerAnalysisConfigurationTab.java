package org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.ui;

import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.Platform;
import org.eclipse.debug.core.ILaunchConfiguration;
import org.eclipse.debug.core.ILaunchConfigurationWorkingCopy;
import org.eclipse.debug.ui.AbstractLaunchConfigurationTab;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Label;
import org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.constants.Constants;


/**
 * Configuration Tab for the Attacker Analyis in the Launch-Configuration
 *
 * @author majuwa
 *
 */
public class AttackerAnalysisConfigurationTab extends AbstractLaunchConfigurationTab {


    private Button checkBox;

    @Override
    public boolean isValid(final ILaunchConfiguration launchConfig) {
        return true;
    }

    /**
     * @wbp.parser.entryPoint
     */
    @Override
    public void createControl(Composite parent) {

        var comp = new Composite(parent, SWT.NONE);
        final var layout = new GridLayout();
        comp.setLayout(layout);
        setControl(comp);

        var text = new Label(comp, 0);
        text.setText("Options");

        this.checkBox = new Button(comp, SWT.CHECK);
        this.checkBox.setText(Constants.GRAPH_CREATION_LABEL);
        this.checkBox.addSelectionListener(new SelectionAdapter() {

            @Override
            public void widgetSelected(SelectionEvent event) {
                AttackerAnalysisConfigurationTab.this.setDirty(true);
                AttackerAnalysisConfigurationTab.this.updateLaunchConfigurationDialog();
            }
        });

    }

    @Override
    public void setDefaults(ILaunchConfigurationWorkingCopy configuration) {
        configuration.setAttribute(Constants.GRAPH_CREATION_LABEL, false);

    }

    @Override
    public void initializeFrom(ILaunchConfiguration configuration) {
        try {
            var previousConfiguration = configuration.getAttribute(Constants.GRAPH_CREATION_LABEL, false);
            this.checkBox.setSelection(previousConfiguration);
        } catch (CoreException e) {
            Platform.getLog(getClass()).error("Could not load from saved configuration", e);
        }

    }

    @Override
    public void performApply(ILaunchConfigurationWorkingCopy configuration) {
        var selection = this.checkBox.getSelection();
        configuration.setAttribute(Constants.GRAPH_CREATION_LABEL, selection);

    }

    @Override
    public String getName() {
        return "Analysis Configuration";
    }

}
