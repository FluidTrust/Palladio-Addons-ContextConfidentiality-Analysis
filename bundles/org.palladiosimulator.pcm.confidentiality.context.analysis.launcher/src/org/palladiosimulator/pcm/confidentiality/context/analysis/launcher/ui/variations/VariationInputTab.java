package org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.ui.variations;

import org.eclipse.core.runtime.CoreException;
import org.eclipse.debug.core.ILaunchConfiguration;
import org.eclipse.debug.core.ILaunchConfigurationWorkingCopy;
import org.eclipse.debug.ui.AbstractLaunchConfigurationTab;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Text;
import org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.constants.Constants;

import de.uka.ipd.sdq.workflow.launchconfig.tabs.TabHelper;

//TODO use Resourcebundles for Strings. ResourceBundle.getBundle
/**
 * Main configuration tab for the launch configuration
 *
 * @author Mirko Sowa
 * @author majuwa
 *
 */
public class VariationInputTab extends AbstractLaunchConfigurationTab {

    private final InitTaskExecutor initTaskExecutor = new InitTaskExecutor();

    private Composite comp;

    private Text variationTextField;

    @Override
    public String getName() {
        return Constants.NAME;
    }

    @Override
    public String getMessage() {
        return "Please select specified files.";
    }

    @Override
    public boolean isValid(final ILaunchConfiguration launchConfig) {
        //        return !repositoryTextField.getText().isEmpty() && !allocationTextField.getText().isEmpty()
        //                && !contextTextField.getText().isEmpty() && isURIexistent(repositoryTextField.getText())
        //                && isURIexistent(allocationTextField.getText()) && isURIexistent(contextTextField.getText());
        // FIXME
        return true;
    }

    @Override
    public void setDefaults(final ILaunchConfigurationWorkingCopy configuration) {
        this.initTaskExecutor.runInitTask(() -> {
            configuration.setAttribute(Constants.VARIATION_MODEL_LABEL, "");
        });
    }

    @Override
    public void initializeFrom(final ILaunchConfiguration configuration) {
        this.initTaskExecutor.runInitTask(() -> {
            this.variationTextField.setText("");

            try {
                this.variationTextField
                        .setText(configuration.getAttribute(Constants.VARIATION_MODEL_LABEL, ""));

            } catch (final CoreException e) {
                // TODO expection handling
            }
        });
    }

    @Override
    public void performApply(final ILaunchConfigurationWorkingCopy configuration) {
        configuration.setAttribute(Constants.VARIATION_MODEL_LABEL, this.variationTextField.getText());
    }

    @Override
    public void createControl(final Composite parent) {

        /* Modify listener for text input changes, sets dirty */
        final ModifyListener modifyListener = e -> {
            if (!VariationInputTab.this.initTaskExecutor.isInitTaskRunning()) {
                VariationInputTab.this.setDirty(true);
                VariationInputTab.this.updateLaunchConfigurationDialog();
            }
        };
        final SelectionListener selectionListener = new SelectionListener() {

            @Override
            public void widgetSelected(final SelectionEvent e) {
                VariationInputTab.this.setDirty(true);
                VariationInputTab.this.updateLaunchConfigurationDialog();
            }

            @Override
            public void widgetDefaultSelected(final SelectionEvent e) {
                // TODO Auto-generated method stub

            }

        };

        this.comp = new Composite(parent, SWT.NONE);
        final var layout = new GridLayout();
        this.comp.setLayout(layout);
        setControl(this.comp);

        /* VariationModel */

        this.variationTextField = new Text(this.comp, SWT.BORDER);
        this.variationTextField.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
        TabHelper.createFileInputSection(this.comp, modifyListener, Constants.VARIATION_MODEL_LABEL,
                new String[] { "*.uncertaintyvariationmodel" }, this.variationTextField,
                Display.getCurrent().getActiveShell(), "");


    }


}
