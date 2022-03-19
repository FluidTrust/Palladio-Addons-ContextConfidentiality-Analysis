/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AssemblyContextDetailContainer;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;

import java.util.Collection;

import org.eclipse.emf.common.notify.NotificationChain;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.InternalEObject;

import org.eclipse.emf.ecore.impl.MinimalEObjectImpl;

import org.eclipse.emf.ecore.util.EObjectContainmentEList;
import org.eclipse.emf.ecore.util.InternalEList;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Assembly Context Detail Container</b></em>'.
 * <!-- end-user-doc -->
 * <p>
 * The following features are implemented:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.AssemblyContextDetailContainerImpl#getCompromisedassembly <em>Compromisedassembly</em>}</li>
 * </ul>
 *
 * @generated
 */
public class AssemblyContextDetailContainerImpl extends MinimalEObjectImpl.Container implements AssemblyContextDetailContainer
{
	/**
	 * The cached value of the '{@link #getCompromisedassembly() <em>Compromisedassembly</em>}' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getCompromisedassembly()
	 * @generated
	 * @ordered
	 */
	protected EList<AssemblyContextDetail> compromisedassembly;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected AssemblyContextDetailContainerImpl()
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
		return KAMP4attackModificationmarksPackage.Literals.ASSEMBLY_CONTEXT_DETAIL_CONTAINER;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EList<AssemblyContextDetail> getCompromisedassembly()
	{
		if (compromisedassembly == null)
		{
			compromisedassembly = new EObjectContainmentEList<AssemblyContextDetail>(AssemblyContextDetail.class, this, KAMP4attackModificationmarksPackage.ASSEMBLY_CONTEXT_DETAIL_CONTAINER__COMPROMISEDASSEMBLY);
		}
		return compromisedassembly;
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
			case KAMP4attackModificationmarksPackage.ASSEMBLY_CONTEXT_DETAIL_CONTAINER__COMPROMISEDASSEMBLY:
				return ((InternalEList<?>)getCompromisedassembly()).basicRemove(otherEnd, msgs);
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
			case KAMP4attackModificationmarksPackage.ASSEMBLY_CONTEXT_DETAIL_CONTAINER__COMPROMISEDASSEMBLY:
				return getCompromisedassembly();
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
			case KAMP4attackModificationmarksPackage.ASSEMBLY_CONTEXT_DETAIL_CONTAINER__COMPROMISEDASSEMBLY:
				getCompromisedassembly().clear();
				getCompromisedassembly().addAll((Collection<? extends AssemblyContextDetail>)newValue);
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
			case KAMP4attackModificationmarksPackage.ASSEMBLY_CONTEXT_DETAIL_CONTAINER__COMPROMISEDASSEMBLY:
				getCompromisedassembly().clear();
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
			case KAMP4attackModificationmarksPackage.ASSEMBLY_CONTEXT_DETAIL_CONTAINER__COMPROMISEDASSEMBLY:
				return compromisedassembly != null && !compromisedassembly.isEmpty();
		}
		return super.eIsSet(featureID);
	}

} //AssemblyContextDetailContainerImpl
