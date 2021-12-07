/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl;

import edu.kit.ipd.sdq.kamp.model.modificationmarks.ChangePropagationStep;

import edu.kit.ipd.sdq.kamp.model.modificationmarks.impl.AbstractModificationRepositoryImpl;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AbstractKAMP4attackModificationRepository;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackSeedModifications;

import org.eclipse.emf.common.notify.NotificationChain;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EClass;

import org.eclipse.emf.ecore.util.EObjectContainmentEList;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Abstract KAMP 4attack Modification Repository</b></em>'.
 * <!-- end-user-doc -->
 *
 * @generated
 */
public abstract class AbstractKAMP4attackModificationRepositoryImpl<T extends KAMP4attackSeedModifications> extends AbstractModificationRepositoryImpl<T, ChangePropagationStep> implements AbstractKAMP4attackModificationRepository<T>
{
	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected AbstractKAMP4attackModificationRepositoryImpl()
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
		return KAMP4attackModificationmarksPackage.Literals.ABSTRACT_KAMP_4ATTACK_MODIFICATION_REPOSITORY;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * This is specialized for the more specific type known in this context.
	 * @generated
	 */
	@Override
	public NotificationChain basicSetSeedModifications(T newSeedModifications, NotificationChain msgs)
	{
		return super.basicSetSeedModifications(newSeedModifications, msgs);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * This is specialized for the more specific element type known in this context.
	 * @generated
	 */
	@Override
	public EList<ChangePropagationStep> getChangePropagationSteps()
	{
		if (changePropagationSteps == null)
		{
			changePropagationSteps = new EObjectContainmentEList<ChangePropagationStep>(ChangePropagationStep.class, this, KAMP4attackModificationmarksPackage.ABSTRACT_KAMP_4ATTACK_MODIFICATION_REPOSITORY__CHANGE_PROPAGATION_STEPS);
		}
		return changePropagationSteps;
	}

} //AbstractKAMP4attackModificationRepositoryImpl
