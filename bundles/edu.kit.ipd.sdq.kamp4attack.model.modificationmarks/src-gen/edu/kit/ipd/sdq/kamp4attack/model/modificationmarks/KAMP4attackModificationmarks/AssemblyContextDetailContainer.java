/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EObject;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Assembly Context Detail Container</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AssemblyContextDetailContainer#getCompromisedassembly <em>Compromisedassembly</em>}</li>
 * </ul>
 *
 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getAssemblyContextDetailContainer()
 * @model
 * @generated
 */
public interface AssemblyContextDetailContainer extends EObject
{
	/**
	 * Returns the value of the '<em><b>Compromisedassembly</b></em>' containment reference list.
	 * The list contents are of type {@link org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail}.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Compromisedassembly</em>' containment reference list.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getAssemblyContextDetailContainer_Compromisedassembly()
	 * @model containment="true"
	 * @generated
	 */
	EList<AssemblyContextDetail> getCompromisedassembly();

} // AssemblyContextDetailContainer
