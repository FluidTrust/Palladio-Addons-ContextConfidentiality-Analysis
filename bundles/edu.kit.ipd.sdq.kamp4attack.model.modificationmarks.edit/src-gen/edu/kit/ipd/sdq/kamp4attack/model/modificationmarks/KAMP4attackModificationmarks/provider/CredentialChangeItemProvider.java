/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.provider;


import edu.kit.ipd.sdq.kamp.model.modificationmarks.provider.ChangePropagationStepItemProvider;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;

import java.util.Collection;
import java.util.List;

import org.eclipse.emf.common.notify.AdapterFactory;
import org.eclipse.emf.common.notify.Notification;

import org.eclipse.emf.common.util.ResourceLocator;

import org.eclipse.emf.ecore.EStructuralFeature;

import org.eclipse.emf.edit.provider.ComposeableAdapterFactory;
import org.eclipse.emf.edit.provider.IItemPropertyDescriptor;
import org.eclipse.emf.edit.provider.ItemPropertyDescriptor;
import org.eclipse.emf.edit.provider.ViewerNotification;

/**
 * This is the item provider adapter for a {@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange} object.
 * <!-- begin-user-doc -->
 * <!-- end-user-doc -->
 * @generated
 */
public class CredentialChangeItemProvider extends ChangePropagationStepItemProvider
{
	/**
	 * This constructs an instance from a factory and a notifier.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public CredentialChangeItemProvider(AdapterFactory adapterFactory)
	{
		super(adapterFactory);
	}

	/**
	 * This returns the property descriptors for the adapted class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public List<IItemPropertyDescriptor> getPropertyDescriptors(Object object)
	{
		if (itemPropertyDescriptors == null)
		{
			super.getPropertyDescriptors(object);

			addChangedPropertyDescriptor(object);
			addAssemblycontextdetailcontainerPropertyDescriptor(object);
		}
		return itemPropertyDescriptors;
	}

	/**
	 * This adds a property descriptor for the Changed feature.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected void addChangedPropertyDescriptor(Object object)
	{
		itemPropertyDescriptors.add
			(createItemPropertyDescriptor
				(((ComposeableAdapterFactory)adapterFactory).getRootAdapterFactory(),
				 getResourceLocator(),
				 getString("_UI_CredentialChange_changed_feature"),
				 getString("_UI_PropertyDescriptor_description", "_UI_CredentialChange_changed_feature", "_UI_CredentialChange_type"),
				 KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__CHANGED,
				 true,
				 false,
				 false,
				 ItemPropertyDescriptor.BOOLEAN_VALUE_IMAGE,
				 null,
				 null));
	}

	/**
	 * This adds a property descriptor for the Assemblycontextdetailcontainer feature.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected void addAssemblycontextdetailcontainerPropertyDescriptor(Object object)
	{
		itemPropertyDescriptors.add
			(createItemPropertyDescriptor
				(((ComposeableAdapterFactory)adapterFactory).getRootAdapterFactory(),
				 getResourceLocator(),
				 getString("_UI_CredentialChange_assemblycontextdetailcontainer_feature"),
				 getString("_UI_PropertyDescriptor_description", "_UI_CredentialChange_assemblycontextdetailcontainer_feature", "_UI_CredentialChange_type"),
				 KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__ASSEMBLYCONTEXTDETAILCONTAINER,
				 true,
				 false,
				 true,
				 null,
				 null,
				 null));
	}

	/**
	 * This specifies how to implement {@link #getChildren} and is used to deduce an appropriate feature for an
	 * {@link org.eclipse.emf.edit.command.AddCommand}, {@link org.eclipse.emf.edit.command.RemoveCommand} or
	 * {@link org.eclipse.emf.edit.command.MoveCommand} in {@link #createCommand}.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public Collection<? extends EStructuralFeature> getChildrenFeatures(Object object)
	{
		if (childrenFeatures == null)
		{
			super.getChildrenFeatures(object);
			childrenFeatures.add(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE);
			childrenFeatures.add(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__CONTEXTCHANGE);
			childrenFeatures.add(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__COMPROMISEDLINKINGRESOURCE);
			childrenFeatures.add(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__COMPROMISEDSERVICE);
			childrenFeatures.add(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER);
			childrenFeatures.add(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__COMPROMISEDDATA);
			childrenFeatures.add(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__DATAMODELCONTAINER);
			childrenFeatures.add(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__COMPROMISEDASSEMBLY);
			childrenFeatures.add(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__ASSEMBLYCONTEXTDETAILCONTAINER);
		}
		return childrenFeatures;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	protected EStructuralFeature getChildFeature(Object object, Object child)
	{
		// Check the type of the specified child object and return the proper feature to use for
		// adding (see {@link AddCommand}) it as a child.

		return super.getChildFeature(object, child);
	}

	/**
	 * This returns CredentialChange.gif.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public Object getImage(Object object)
	{
		return overlayImage(object, getResourceLocator().getImage("full/obj16/CredentialChange"));
	}

	/**
	 * This returns the label text for the adapted class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public String getText(Object object)
	{
		CredentialChange credentialChange = (CredentialChange)object;
		return getString("_UI_CredentialChange_type") + " " + credentialChange.isChanged();
	}


	/**
	 * This handles model notifications by calling {@link #updateChildren} to update any cached
	 * children and by creating a viewer notification, which it passes to {@link #fireNotifyChanged}.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public void notifyChanged(Notification notification)
	{
		updateChildren(notification);

		switch (notification.getFeatureID(CredentialChange.class))
		{
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__CHANGED:
				fireNotifyChanged(new ViewerNotification(notification, notification.getNotifier(), false, true));
				return;
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE:
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__CONTEXTCHANGE:
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDLINKINGRESOURCE:
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDSERVICE:
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER:
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDDATA:
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__DATAMODELCONTAINER:
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDASSEMBLY:
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__ASSEMBLYCONTEXTDETAILCONTAINER:
				fireNotifyChanged(new ViewerNotification(notification, notification.getNotifier(), true, false));
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
	protected void collectNewChildDescriptors(Collection<Object> newChildDescriptors, Object object)
	{
		super.collectNewChildDescriptors(newChildDescriptors, object);

		newChildDescriptors.add
			(createChildParameter
				(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE,
				 KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedResource()));

		newChildDescriptors.add
			(createChildParameter
				(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__CONTEXTCHANGE,
				 KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange()));

		newChildDescriptors.add
			(createChildParameter
				(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__COMPROMISEDLINKINGRESOURCE,
				 KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedLinkingResource()));

		newChildDescriptors.add
			(createChildParameter
				(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__COMPROMISEDSERVICE,
				 KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedService()));

		newChildDescriptors.add
			(createChildParameter
				(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER,
				 KAMP4attackModificationmarksFactory.eINSTANCE.createServiceRestrictionContainer()));

		newChildDescriptors.add
			(createChildParameter
				(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__COMPROMISEDDATA,
				 KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedData()));

		newChildDescriptors.add
			(createChildParameter
				(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__DATAMODELCONTAINER,
				 KAMP4attackModificationmarksFactory.eINSTANCE.createDatamodelContainer()));

		newChildDescriptors.add
			(createChildParameter
				(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__COMPROMISEDASSEMBLY,
				 KAMP4attackModificationmarksFactory.eINSTANCE.createCompromisedAssembly()));

		newChildDescriptors.add
			(createChildParameter
				(KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE__ASSEMBLYCONTEXTDETAILCONTAINER,
				 KAMP4attackModificationmarksFactory.eINSTANCE.createAssemblyContextDetailContainer()));
	}

	/**
	 * Return the resource locator for this item provider's resources.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public ResourceLocator getResourceLocator()
	{
		return KAMP4attackModificationsmarksEditPlugin.INSTANCE;
	}

}
