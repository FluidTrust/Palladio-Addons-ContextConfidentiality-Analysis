/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EObject;

import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Service Restriction Container</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ServiceRestrictionContainer#getServicerestriction <em>Servicerestriction</em>}</li>
 * </ul>
 *
 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getServiceRestrictionContainer()
 * @model
 * @generated
 */
public interface ServiceRestrictionContainer extends EObject
{
	/**
	 * Returns the value of the '<em><b>Servicerestriction</b></em>' containment reference list.
	 * The list contents are of type {@link org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction}.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Servicerestriction</em>' containment reference list.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getServiceRestrictionContainer_Servicerestriction()
	 * @model containment="true"
	 * @generated
	 */
	EList<ServiceRestriction> getServicerestriction();

} // ServiceRestrictionContainer
