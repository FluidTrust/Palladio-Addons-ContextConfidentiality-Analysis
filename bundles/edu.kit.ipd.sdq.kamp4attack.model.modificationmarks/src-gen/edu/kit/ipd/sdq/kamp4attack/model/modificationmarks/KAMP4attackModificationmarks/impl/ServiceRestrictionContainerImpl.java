/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ServiceRestrictionContainer;

import java.util.Collection;

import org.eclipse.emf.common.notify.NotificationChain;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.InternalEObject;

import org.eclipse.emf.ecore.impl.MinimalEObjectImpl;

import org.eclipse.emf.ecore.util.EObjectContainmentEList;
import org.eclipse.emf.ecore.util.InternalEList;

import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Service Restriction Container</b></em>'.
 * <!-- end-user-doc -->
 * <p>
 * The following features are implemented:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ServiceRestrictionContainerImpl#getServicerestriction <em>Servicerestriction</em>}</li>
 * </ul>
 *
 * @generated
 */
public class ServiceRestrictionContainerImpl extends MinimalEObjectImpl.Container implements ServiceRestrictionContainer
{
	/**
	 * The cached value of the '{@link #getServicerestriction() <em>Servicerestriction</em>}' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getServicerestriction()
	 * @generated
	 * @ordered
	 */
	protected EList<ServiceRestriction> servicerestriction;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected ServiceRestrictionContainerImpl()
	{
		super();
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	protected EClass eStaticClass()
	{
		return KAMP4attackModificationmarksPackage.Literals.SERVICE_RESTRICTION_CONTAINER;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EList<ServiceRestriction> getServicerestriction()
	{
		if (servicerestriction == null)
		{
			servicerestriction = new EObjectContainmentEList<ServiceRestriction>(ServiceRestriction.class, this, KAMP4attackModificationmarksPackage.SERVICE_RESTRICTION_CONTAINER__SERVICERESTRICTION);
		}
		return servicerestriction;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public NotificationChain eInverseRemove(InternalEObject otherEnd, int featureID, NotificationChain msgs)
	{
		switch (featureID)
		{
			case KAMP4attackModificationmarksPackage.SERVICE_RESTRICTION_CONTAINER__SERVICERESTRICTION:
				return ((InternalEList<?>)getServicerestriction()).basicRemove(otherEnd, msgs);
		}
		return super.eInverseRemove(otherEnd, featureID, msgs);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public Object eGet(int featureID, boolean resolve, boolean coreType)
	{
		switch (featureID)
		{
			case KAMP4attackModificationmarksPackage.SERVICE_RESTRICTION_CONTAINER__SERVICERESTRICTION:
				return getServicerestriction();
		}
		return super.eGet(featureID, resolve, coreType);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@SuppressWarnings("unchecked")
	@Override
	public void eSet(int featureID, Object newValue)
	{
		switch (featureID)
		{
			case KAMP4attackModificationmarksPackage.SERVICE_RESTRICTION_CONTAINER__SERVICERESTRICTION:
				getServicerestriction().clear();
				getServicerestriction().addAll((Collection<? extends ServiceRestriction>)newValue);
				return;
		}
		super.eSet(featureID, newValue);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public void eUnset(int featureID)
	{
		switch (featureID)
		{
			case KAMP4attackModificationmarksPackage.SERVICE_RESTRICTION_CONTAINER__SERVICERESTRICTION:
				getServicerestriction().clear();
				return;
		}
		super.eUnset(featureID);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public boolean eIsSet(int featureID)
	{
		switch (featureID)
		{
			case KAMP4attackModificationmarksPackage.SERVICE_RESTRICTION_CONTAINER__SERVICERESTRICTION:
				return servicerestriction != null && !servicerestriction.isEmpty();
		}
		return super.eIsSet(featureID);
	}

} //ServiceRestrictionContainerImpl
