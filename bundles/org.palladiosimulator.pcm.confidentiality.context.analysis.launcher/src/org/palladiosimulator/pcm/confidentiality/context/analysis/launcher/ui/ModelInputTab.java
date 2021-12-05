package org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.ui;

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
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Text;
import org.palladiosimulator.pcm.confidentiality.context.analysis.launcher.constants.Constants;

import de.uka.ipd.sdq.workflow.launchconfig.tabs.TabHelper;

//TODO use Resourcebundles for Strings. ResourceBundle.getBundle
/**
 * Main configuration tab for the launch configuration
 *
 * @author Mirko Sowa
 *
 */
public class ModelInputTab extends AbstractLaunchConfigurationTab {

    private final InitTaskExecutor initTaskExecutor = new InitTaskExecutor();

    private Composite comp;

    private Text repositoryTextField;
    private Text usageTextField;
    private Text allocationTextField;
    private Text contextTextField;
    private Text dataTextField;
    private Text adversaryTextField;
    private Text modificationTextField;
    private Combo analysisCombo;

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
            configuration.setAttribute(Constants.REPOSITORY_MODEL_LABEL, "");
            configuration.setAttribute(Constants.ALLOCATION_MODEL_LABEL, "");
            configuration.setAttribute(Constants.CONTEXT_MODEL_LABEL, "");

        });
    }

    @Override
    public void initializeFrom(final ILaunchConfiguration configuration) {
        this.initTaskExecutor.runInitTask(() -> {
            this.repositoryTextField.setText("");
            this.allocationTextField.setText("");
            this.contextTextField.setText("");

            try {
                this.repositoryTextField
                        .setText(configuration.getAttribute(Constants.REPOSITORY_MODEL_LABEL, ""));
                this.allocationTextField
                        .setText(configuration.getAttribute(Constants.ALLOCATION_MODEL_LABEL, ""));
                this.contextTextField
                        .setText(configuration.getAttribute(Constants.CONTEXT_MODEL_LABEL, ""));
                this.dataTextField.setText(configuration.getAttribute(Constants.DATA_MODEL_LABEL, ""));
                this.adversaryTextField
                        .setText(configuration.getAttribute(Constants.ATTACKER_MODEL_LABEL, ""));
                this.usageTextField.setText(configuration.getAttribute(Constants.USAGE_MODEL_LABEL, ""));
                this.analysisCombo.setText(configuration.getAttribute(Constants.ANALYSIS_TYPE_LABEL, ""));
                this.modificationTextField
                        .setText(configuration.getAttribute(Constants.MODIFIACTION_MODEL_LABEL, ""));

            } catch (final CoreException e) {
                // TODO expection handling
            }
        });
    }

    @Override
    public void performApply(final ILaunchConfigurationWorkingCopy configuration) {
        configuration.setAttribute(Constants.REPOSITORY_MODEL_LABEL, this.repositoryTextField.getText());
        configuration.setAttribute(Constants.ALLOCATION_MODEL_LABEL, this.allocationTextField.getText());
        configuration.setAttribute(Constants.CONTEXT_MODEL_LABEL, this.contextTextField.getText());
        configuration.setAttribute(Constants.DATA_MODEL_LABEL, this.dataTextField.getText());
        configuration.setAttribute(Constants.ATTACKER_MODEL_LABEL, this.adversaryTextField.getText());
        configuration.setAttribute(Constants.ANALYSIS_TYPE_LABEL, this.analysisCombo.getText());
        configuration.setAttribute(Constants.USAGE_MODEL_LABEL, this.usageTextField.getText());
        configuration.setAttribute(Constants.MODIFIACTION_MODEL_LABEL,
                this.modificationTextField.getText());
    }

    @Override
    public void createControl(final Composite parent) {

        /* Modify listener for text input changes, sets dirty */
        final ModifyListener modifyListener = e -> {
            if (!ModelInputTab.this.initTaskExecutor.isInitTaskRunning()) {
                ModelInputTab.this.setDirty(true);
                ModelInputTab.this.updateLaunchConfigurationDialog();
            }
        };
        final SelectionListener selectionListener = new SelectionListener() {

            @Override
            public void widgetSelected(final SelectionEvent e) {
                ModelInputTab.this.setDirty(true);
                ModelInputTab.this.updateLaunchConfigurationDialog();
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

        final var analysisGroup = new Group(this.comp, SWT.NONE);
        analysisGroup.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
        analysisGroup.setText(Constants.ANALYSIS_TYPE_LABEL);
        analysisGroup.setLayout(layout);

        this.analysisCombo = new Combo(analysisGroup, SWT.DROP_DOWN);

        final var items = new String[] { "Scenario", "Insider", "Attack surface" };

        this.analysisCombo.setItems(items);

        this.analysisCombo.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
        this.analysisCombo.addSelectionListener(selectionListener);
        this.analysisCombo.clearSelection();

        /* Usage Model */

        this.usageTextField = new Text(this.comp, SWT.BORDER);
        this.usageTextField.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
        TabHelper.createFileInputSection(this.comp, modifyListener, Constants.USAGE_MODEL_LABEL,
                new String[] { "*.usagemodel" }, this.usageTextField, Display.getCurrent().getActiveShell(), "");

        /* Repository */

        this.repositoryTextField = new Text(this.comp, SWT.BORDER);
        this.repositoryTextField.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
        TabHelper.createFileInputSection(this.comp, modifyListener, Constants.REPOSITORY_MODEL_LABEL,
                new String[] { "*.repository" }, this.repositoryTextField, Display.getCurrent().getActiveShell(), "");

        /* Allocation-Model */

        this.allocationTextField = new Text(this.comp, SWT.BORDER);
        this.allocationTextField.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
        TabHelper.createFileInputSection(this.comp, modifyListener, Constants.ALLOCATION_MODEL_LABEL,
                new String[] { "*.allocation" }, this.allocationTextField, Display.getCurrent().getActiveShell(), "");

        /* Context-Model */

        this.contextTextField = new Text(this.comp, SWT.BORDER);
        this.contextTextField.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
        TabHelper.createFileInputSection(this.comp, modifyListener, Constants.CONTEXT_MODEL_LABEL,
                new String[] { "*.context" }, this.contextTextField, Display.getCurrent().getActiveShell(), "");

        this.dataTextField = new Text(this.comp, SWT.BORDER);
        this.dataTextField.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
        TabHelper.createFileInputSection(this.comp, modifyListener, Constants.DATA_MODEL_LABEL,
                new String[] { "*.confidentiality" }, this.dataTextField, Display.getCurrent().getActiveShell(), "");

        this.adversaryTextField = new Text(this.comp, SWT.BORDER);
        this.adversaryTextField.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
        TabHelper.createFileInputSection(this.comp, modifyListener, Constants.ATTACKER_MODEL_LABEL,
                new String[] { "*.attacker" }, this.adversaryTextField, Display.getCurrent().getActiveShell(), "");

        this.modificationTextField = new Text(this.comp, SWT.BORDER);
        this.modificationTextField.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
        TabHelper.createFileInputSection(this.comp, modifyListener, Constants.MODIFIACTION_MODEL_LABEL,
                new String[] { "*.kamp4attackmodificationmarks" }, this.modificationTextField,
                Display.getCurrent().getActiveShell(), "");
    }


}
