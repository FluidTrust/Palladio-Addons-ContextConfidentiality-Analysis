/**
 */
package org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.provider;

import java.util.Collection;
import java.util.List;
import org.eclipse.emf.common.notify.AdapterFactory;
import org.eclipse.emf.common.notify.Notification;

import org.eclipse.emf.common.util.ResourceLocator;

import org.eclipse.emf.edit.provider.ComposeableAdapterFactory;
import org.eclipse.emf.edit.provider.IEditingDomainItemProvider;
import org.eclipse.emf.edit.provider.IItemLabelProvider;
import org.eclipse.emf.edit.provider.IItemPropertyDescriptor;
import org.eclipse.emf.edit.provider.IItemPropertySource;
import org.eclipse.emf.edit.provider.IStructuredItemContentProvider;
import org.eclipse.emf.edit.provider.ITreeItemContentProvider;
import org.eclipse.emf.edit.provider.ItemPropertyDescriptor;
import org.eclipse.emf.edit.provider.ItemProviderAdapter;
import org.eclipse.emf.edit.provider.ViewerNotification;

import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.OutputmodelPackage;
import org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput;

/**
 * This is the item provider adapter for a {@link org.palladiosimulator.pcm.confidentiality.context.analysis.outputmodel.ScenarioOutput} object.
 * <!-- begin-user-doc -->
 * <!-- end-user-doc -->
 * @generated
 */
public class ScenarioOutputItemProvider extends ItemProviderAdapter implements IEditingDomainItemProvider,
        IStructuredItemContentProvider, ITreeItemContentProvider, IItemLabelProvider, IItemPropertySource {
    /**
     * This constructs an instance from a factory and a notifier.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    public ScenarioOutputItemProvider(AdapterFactory adapterFactory) {
        super(adapterFactory);
    }

    /**
     * This returns the property descriptors for the adapted class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    @Override
    public List<IItemPropertyDescriptor> getPropertyDescriptors(Object object) {
        if (itemPropertyDescriptors == null) {
            super.getPropertyDescriptors(object);

            addResultPropertyDescriptor(object);
            addScenarioPropertyDescriptor(object);
            addOperationsignaturePropertyDescriptor(object);
            addOperationinterfacePropertyDescriptor(object);
            addConnectorPropertyDescriptor(object);
            addRequestorSetPropertyDescriptor(object);
            addRequiredSetsPropertyDescriptor(object);
        }
        return itemPropertyDescriptors;
    }

    /**
     * This adds a property descriptor for the Result feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    protected void addResultPropertyDescriptor(Object object) {
        itemPropertyDescriptors
                .add(createItemPropertyDescriptor(((ComposeableAdapterFactory) adapterFactory).getRootAdapterFactory(),
                        getResourceLocator(), getString("_UI_ScenarioOutput_result_feature"),
                        getString("_UI_PropertyDescriptor_description", "_UI_ScenarioOutput_result_feature",
                                "_UI_ScenarioOutput_type"),
                        OutputmodelPackage.Literals.SCENARIO_OUTPUT__RESULT, true, false, false,
                        ItemPropertyDescriptor.BOOLEAN_VALUE_IMAGE, null, null));
    }

    /**
     * This adds a property descriptor for the Scenario feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    protected void addScenarioPropertyDescriptor(Object object) {
        itemPropertyDescriptors
                .add(createItemPropertyDescriptor(((ComposeableAdapterFactory) adapterFactory).getRootAdapterFactory(),
                        getResourceLocator(), getString("_UI_ScenarioOutput_scenario_feature"),
                        getString("_UI_PropertyDescriptor_description", "_UI_ScenarioOutput_scenario_feature",
                                "_UI_ScenarioOutput_type"),
                        OutputmodelPackage.Literals.SCENARIO_OUTPUT__SCENARIO, true, false, true, null, null, null));
    }

    /**
     * This adds a property descriptor for the Operationsignature feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    protected void addOperationsignaturePropertyDescriptor(Object object) {
        itemPropertyDescriptors.add(createItemPropertyDescriptor(
                ((ComposeableAdapterFactory) adapterFactory).getRootAdapterFactory(), getResourceLocator(),
                getString("_UI_ScenarioOutput_operationsignature_feature"),
                getString("_UI_PropertyDescriptor_description", "_UI_ScenarioOutput_operationsignature_feature",
                        "_UI_ScenarioOutput_type"),
                OutputmodelPackage.Literals.SCENARIO_OUTPUT__OPERATIONSIGNATURE, true, false, true, null, null, null));
    }

    /**
     * This adds a property descriptor for the Operationinterface feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    protected void addOperationinterfacePropertyDescriptor(Object object) {
        itemPropertyDescriptors.add(createItemPropertyDescriptor(
                ((ComposeableAdapterFactory) adapterFactory).getRootAdapterFactory(), getResourceLocator(),
                getString("_UI_ScenarioOutput_operationinterface_feature"),
                getString("_UI_PropertyDescriptor_description", "_UI_ScenarioOutput_operationinterface_feature",
                        "_UI_ScenarioOutput_type"),
                OutputmodelPackage.Literals.SCENARIO_OUTPUT__OPERATIONINTERFACE, true, false, true, null, null, null));
    }

    /**
     * This adds a property descriptor for the Connector feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    protected void addConnectorPropertyDescriptor(Object object) {
        itemPropertyDescriptors
                .add(createItemPropertyDescriptor(((ComposeableAdapterFactory) adapterFactory).getRootAdapterFactory(),
                        getResourceLocator(), getString("_UI_ScenarioOutput_connector_feature"),
                        getString("_UI_PropertyDescriptor_description", "_UI_ScenarioOutput_connector_feature",
                                "_UI_ScenarioOutput_type"),
                        OutputmodelPackage.Literals.SCENARIO_OUTPUT__CONNECTOR, true, false, true, null, null, null));
    }

    /**
     * This adds a property descriptor for the Requestor Set feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    protected void addRequestorSetPropertyDescriptor(Object object) {
        itemPropertyDescriptors
                .add(createItemPropertyDescriptor(((ComposeableAdapterFactory) adapterFactory).getRootAdapterFactory(),
                        getResourceLocator(), getString("_UI_ScenarioOutput_requestorSet_feature"),
                        getString("_UI_PropertyDescriptor_description", "_UI_ScenarioOutput_requestorSet_feature",
                                "_UI_ScenarioOutput_type"),
                        OutputmodelPackage.Literals.SCENARIO_OUTPUT__REQUESTOR_SET, true, false, true, null, null,
                        null));
    }

    /**
     * This adds a property descriptor for the Required Sets feature.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    protected void addRequiredSetsPropertyDescriptor(Object object) {
        itemPropertyDescriptors
                .add(createItemPropertyDescriptor(((ComposeableAdapterFactory) adapterFactory).getRootAdapterFactory(),
                        getResourceLocator(), getString("_UI_ScenarioOutput_requiredSets_feature"),
                        getString("_UI_PropertyDescriptor_description", "_UI_ScenarioOutput_requiredSets_feature",
                                "_UI_ScenarioOutput_type"),
                        OutputmodelPackage.Literals.SCENARIO_OUTPUT__REQUIRED_SETS, true, false, true, null, null,
                        null));
    }

    /**
     * This returns ScenarioOutput.gif.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    @Override
    public Object getImage(Object object) {
        return overlayImage(object, getResourceLocator().getImage("full/obj16/ScenarioOutput"));
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    @Override
    protected boolean shouldComposeCreationImage() {
        return true;
    }

    /**
     * This returns the label text for the adapted class.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    @Override
    public String getText(Object object) {
        ScenarioOutput scenarioOutput = (ScenarioOutput) object;
        return getString("_UI_ScenarioOutput_type") + " " + scenarioOutput.isResult();
    }

    /**
     * This handles model notifications by calling {@link #updateChildren} to update any cached
     * children and by creating a viewer notification, which it passes to {@link #fireNotifyChanged}.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    @Override
    public void notifyChanged(Notification notification) {
        updateChildren(notification);

        switch (notification.getFeatureID(ScenarioOutput.class)) {
        case OutputmodelPackage.SCENARIO_OUTPUT__RESULT:
            fireNotifyChanged(new ViewerNotification(notification, notification.getNotifier(), false, true));
            return;
        }
        super.notifyChanged(notification);
    }

    /**
     * This adds {@link org.eclipse.emf.edit.command.CommandParameter}s describing the children
     * that can be created under this object.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    @Override
    protected void collectNewChildDescriptors(Collection<Object> newChildDescriptors, Object object) {
        super.collectNewChildDescriptors(newChildDescriptors, object);
    }

    /**
     * Return the resource locator for this item provider's resources.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    @Override
    public ResourceLocator getResourceLocator() {
        return OutputmodelEditPlugin.INSTANCE;
    }

}
