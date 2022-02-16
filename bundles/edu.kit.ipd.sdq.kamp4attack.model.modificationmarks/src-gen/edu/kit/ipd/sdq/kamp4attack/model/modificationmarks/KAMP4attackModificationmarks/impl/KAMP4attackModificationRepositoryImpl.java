/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationRepository;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackSeedModifications;

import java.util.Collection;

import org.eclipse.emf.common.notify.Notification;
import org.eclipse.emf.common.notify.NotificationChain;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.InternalEObject;

import org.eclipse.emf.ecore.impl.ENotificationImpl;

import org.eclipse.emf.ecore.util.EObjectContainmentEList;
import org.eclipse.emf.ecore.util.InternalEList;

import org.eclipse.emf.internal.cdo.CDOObjectImpl;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>KAMP 4attack Modification Repository</b></em>'.
 * <!-- end-user-doc -->
 * <p>
 * The following features are implemented:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationRepositoryImpl#getChangePropagationSteps <em>Change Propagation Steps</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationRepositoryImpl#getSeedModifications <em>Seed Modifications</em>}</li>
 * </ul>
 *
 * @generated
 */
public class KAMP4attackModificationRepositoryImpl extends CDOObjectImpl implements KAMP4attackModificationRepository
{
	/**
	 * The cached value of the '{@link #getChangePropagationSteps() <em>Change Propagation Steps</em>}' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getChangePropagationSteps()
	 * @generated
	 * @ordered
	 */
	protected EList<CredentialChange> changePropagationSteps;

	/**
	 * The cached value of the '{@link #getSeedModifications() <em>Seed Modifications</em>}' containment reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getSeedModifications()
	 * @generated
	 * @ordered
	 */
	protected KAMP4attackSeedModifications seedModifications;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected KAMP4attackModificationRepositoryImpl()
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
		return KAMP4attackModificationmarksPackage.Literals.KAMP_4ATTACK_MODIFICATION_REPOSITORY;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EList<CredentialChange> getChangePropagationSteps()
	{
		if (changePropagationSteps == null)
		{
			changePropagationSteps = new EObjectContainmentEList<CredentialChange>(CredentialChange.class, this, KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__CHANGE_PROPAGATION_STEPS);
		}
		return changePropagationSteps;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public KAMP4attackSeedModifications getSeedModifications()
	{
		return seedModifications;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public NotificationChain basicSetSeedModifications(KAMP4attackSeedModifications newSeedModifications, NotificationChain msgs)
	{
		KAMP4attackSeedModifications oldSeedModifications = seedModifications;
		seedModifications = newSeedModifications;
		if (eNotificationRequired())
		{
			ENotificationImpl notification = new ENotificationImpl(this, Notification.SET, KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__SEED_MODIFICATIONS, oldSeedModifications, newSeedModifications);
			if (msgs == null) msgs = notification; else msgs.add(notification);
		}
		return msgs;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public void setSeedModifications(KAMP4attackSeedModifications newSeedModifications)
	{
		if (newSeedModifications != seedModifications)
		{
			NotificationChain msgs = null;
			if (seedModifications != null)
				msgs = ((InternalEObject)seedModifications).eInverseRemove(this, EOPPOSITE_FEATURE_BASE - KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__SEED_MODIFICATIONS, null, msgs);
			if (newSeedModifications != null)
				msgs = ((InternalEObject)newSeedModifications).eInverseAdd(this, EOPPOSITE_FEATURE_BASE - KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__SEED_MODIFICATIONS, null, msgs);
			msgs = basicSetSeedModifications(newSeedModifications, msgs);
			if (msgs != null) msgs.dispatch();
		}
		else if (eNotificationRequired())
			eNotify(new ENotificationImpl(this, Notification.SET, KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__SEED_MODIFICATIONS, newSeedModifications, newSeedModifications));
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
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__CHANGE_PROPAGATION_STEPS:
				return ((InternalEList<?>)getChangePropagationSteps()).basicRemove(otherEnd, msgs);
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__SEED_MODIFICATIONS:
				return basicSetSeedModifications(null, msgs);
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
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__CHANGE_PROPAGATION_STEPS:
				return getChangePropagationSteps();
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__SEED_MODIFICATIONS:
				return getSeedModifications();
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
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__CHANGE_PROPAGATION_STEPS:
				getChangePropagationSteps().clear();
				getChangePropagationSteps().addAll((Collection<? extends CredentialChange>)newValue);
				return;
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__SEED_MODIFICATIONS:
				setSeedModifications((KAMP4attackSeedModifications)newValue);
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
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__CHANGE_PROPAGATION_STEPS:
				getChangePropagationSteps().clear();
				return;
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__SEED_MODIFICATIONS:
				setSeedModifications((KAMP4attackSeedModifications)null);
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
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__CHANGE_PROPAGATION_STEPS:
				return changePropagationSteps != null && !changePropagationSteps.isEmpty();
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY__SEED_MODIFICATIONS:
				return seedModifications != null;
		}
		return super.eIsSet(featureID);
	}

} //KAMP4attackModificationRepositoryImpl
