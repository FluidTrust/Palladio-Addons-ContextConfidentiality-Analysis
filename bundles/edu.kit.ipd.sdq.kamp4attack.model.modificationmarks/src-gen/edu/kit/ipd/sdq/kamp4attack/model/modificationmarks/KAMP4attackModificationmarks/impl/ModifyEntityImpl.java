/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl;

import edu.kit.ipd.sdq.kamp.model.modificationmarks.impl.AbstractModificationImpl;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ModifyEntity;

import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.EObject;

import org.palladiosimulator.pcm.core.entity.Entity;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Modify Entity</b></em>'.
 * <!-- end-user-doc -->
 *
 * @generated
 */
public abstract class ModifyEntityImpl<T extends Entity> extends AbstractModificationImpl<T, EObject> implements ModifyEntity<T>
{
	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected ModifyEntityImpl()
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
		return KAMP4attackModificationmarksPackage.Literals.MODIFY_ENTITY;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * This is specialized for the more specific type known in this context.
	 * @generated
	 */
	@Override
	public void setAffectedElement(T newAffectedElement)
	{
		super.setAffectedElement(newAffectedElement);
	}

} //ModifyEntityImpl
