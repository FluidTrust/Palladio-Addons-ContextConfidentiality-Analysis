/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EObject;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.DatamodelAttacker;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Datamodel Container</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.DatamodelContainer#getDatamodelattacker <em>Datamodelattacker</em>}</li>
 * </ul>
 *
 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getDatamodelContainer()
 * @model
 * @generated
 */
public interface DatamodelContainer extends EObject
{
	/**
	 * Returns the value of the '<em><b>Datamodelattacker</b></em>' containment reference list.
	 * The list contents are of type {@link org.palladiosimulator.pcm.confidentiality.attackerSpecification.DatamodelAttacker}.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Datamodelattacker</em>' containment reference list.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getDatamodelContainer_Datamodelattacker()
	 * @model containment="true"
	 * @generated
	 */
	EList<DatamodelAttacker> getDatamodelattacker();

} // DatamodelContainer
