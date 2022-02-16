/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedService;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;

import org.eclipse.emf.ecore.EClass;

import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Compromised Service</b></em>'.
 * <!-- end-user-doc -->
 *
 * @generated
 */
public class CompromisedServiceImpl extends ModifyEntityImpl<ServiceRestriction> implements CompromisedService
{
	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected CompromisedServiceImpl()
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
		return KAMP4attackModificationmarksPackage.Literals.COMPROMISED_SERVICE;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * This is specialized for the more specific type known in this context.
	 * @generated
	 */
	@Override
	public void setAffectedElement(ServiceRestriction newAffectedElement)
	{
		super.setAffectedElement(newAffectedElement);
	}

} //CompromisedServiceImpl
