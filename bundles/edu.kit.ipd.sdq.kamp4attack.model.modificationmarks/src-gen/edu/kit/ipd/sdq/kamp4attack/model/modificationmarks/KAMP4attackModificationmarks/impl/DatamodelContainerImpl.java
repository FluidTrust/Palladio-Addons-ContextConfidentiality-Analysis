/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.DatamodelContainer;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;

import java.util.Collection;

import org.eclipse.emf.common.notify.NotificationChain;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.InternalEObject;

import org.eclipse.emf.ecore.impl.MinimalEObjectImpl;

import org.eclipse.emf.ecore.util.EObjectContainmentEList;
import org.eclipse.emf.ecore.util.InternalEList;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.DatamodelAttacker;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Datamodel Container</b></em>'.
 * <!-- end-user-doc -->
 * <p>
 * The following features are implemented:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.DatamodelContainerImpl#getDatamodelattacker <em>Datamodelattacker</em>}</li>
 * </ul>
 *
 * @generated
 */
public class DatamodelContainerImpl extends MinimalEObjectImpl.Container implements DatamodelContainer
{
	/**
	 * The cached value of the '{@link #getDatamodelattacker() <em>Datamodelattacker</em>}' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getDatamodelattacker()
	 * @generated
	 * @ordered
	 */
	protected EList<DatamodelAttacker> datamodelattacker;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected DatamodelContainerImpl()
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
		return KAMP4attackModificationmarksPackage.Literals.DATAMODEL_CONTAINER;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EList<DatamodelAttacker> getDatamodelattacker()
	{
		if (datamodelattacker == null)
		{
			datamodelattacker = new EObjectContainmentEList<DatamodelAttacker>(DatamodelAttacker.class, this, KAMP4attackModificationmarksPackage.DATAMODEL_CONTAINER__DATAMODELATTACKER);
		}
		return datamodelattacker;
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
			case KAMP4attackModificationmarksPackage.DATAMODEL_CONTAINER__DATAMODELATTACKER:
				return ((InternalEList<?>)getDatamodelattacker()).basicRemove(otherEnd, msgs);
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
			case KAMP4attackModificationmarksPackage.DATAMODEL_CONTAINER__DATAMODELATTACKER:
				return getDatamodelattacker();
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
			case KAMP4attackModificationmarksPackage.DATAMODEL_CONTAINER__DATAMODELATTACKER:
				getDatamodelattacker().clear();
				getDatamodelattacker().addAll((Collection<? extends DatamodelAttacker>)newValue);
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
			case KAMP4attackModificationmarksPackage.DATAMODEL_CONTAINER__DATAMODELATTACKER:
				getDatamodelattacker().clear();
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
			case KAMP4attackModificationmarksPackage.DATAMODEL_CONTAINER__DATAMODELATTACKER:
				return datamodelattacker != null && !datamodelattacker.isEmpty();
		}
		return super.eIsSet(featureID);
	}

} //DatamodelContainerImpl
