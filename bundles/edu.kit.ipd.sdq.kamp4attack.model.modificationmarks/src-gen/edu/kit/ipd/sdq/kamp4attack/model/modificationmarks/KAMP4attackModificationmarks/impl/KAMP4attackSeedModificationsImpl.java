/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl;

import edu.kit.ipd.sdq.kamp.model.modificationmarks.impl.AbstractSeedModificationsImpl;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AttackerSelection;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackSeedModifications;

import java.util.Collection;

import org.eclipse.emf.common.notify.NotificationChain;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.InternalEObject;

import org.eclipse.emf.ecore.util.EObjectContainmentEList;
import org.eclipse.emf.ecore.util.InternalEList;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>KAMP 4attack Seed Modifications</b></em>'.
 * <!-- end-user-doc -->
 * <p>
 * The following features are implemented:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackSeedModificationsImpl#getAttackcomponent <em>Attackcomponent</em>}</li>
 * </ul>
 *
 * @generated
 */
public class KAMP4attackSeedModificationsImpl extends AbstractSeedModificationsImpl implements KAMP4attackSeedModifications
{
	/**
	 * The cached value of the '{@link #getAttackcomponent() <em>Attackcomponent</em>}' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getAttackcomponent()
	 * @generated
	 * @ordered
	 */
	protected EList<AttackerSelection> attackcomponent;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected KAMP4attackSeedModificationsImpl()
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
		return KAMP4attackModificationmarksPackage.Literals.KAMP_4ATTACK_SEED_MODIFICATIONS;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EList<AttackerSelection> getAttackcomponent()
	{
		if (attackcomponent == null) {
			attackcomponent = new EObjectContainmentEList<AttackerSelection>(AttackerSelection.class, this, KAMP4attackModificationmarksPackage.KAMP_4ATTACK_SEED_MODIFICATIONS__ATTACKCOMPONENT);
		}
		return attackcomponent;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public NotificationChain eInverseRemove(InternalEObject otherEnd, int featureID, NotificationChain msgs)
	{
		switch (featureID) {
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_SEED_MODIFICATIONS__ATTACKCOMPONENT:
				return ((InternalEList<?>)getAttackcomponent()).basicRemove(otherEnd, msgs);
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
		switch (featureID) {
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_SEED_MODIFICATIONS__ATTACKCOMPONENT:
				return getAttackcomponent();
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
		switch (featureID) {
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_SEED_MODIFICATIONS__ATTACKCOMPONENT:
				getAttackcomponent().clear();
				getAttackcomponent().addAll((Collection<? extends AttackerSelection>)newValue);
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
		switch (featureID) {
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_SEED_MODIFICATIONS__ATTACKCOMPONENT:
				getAttackcomponent().clear();
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
		switch (featureID) {
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_SEED_MODIFICATIONS__ATTACKCOMPONENT:
				return attackcomponent != null && !attackcomponent.isEmpty();
		}
		return super.eIsSet(featureID);
	}

} //KAMP4attackSeedModificationsImpl
