/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EObject;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Compromised Assembly Container</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssemblyContainer#getAffectedElements <em>Affected Elements</em>}</li>
 * </ul>
 *
 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getCompromisedAssemblyContainer()
 * @model
 * @generated
 */
public interface CompromisedAssemblyContainer extends EObject {
	/**
	 * Returns the value of the '<em><b>Affected Elements</b></em>' reference list.
	 * The list contents are of type {@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly}.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Affected Elements</em>' reference list.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getCompromisedAssemblyContainer_AffectedElements()
	 * @model required="true"
	 * @generated
	 */
	EList<CompromisedAssembly> getAffectedElements();

} // CompromisedAssemblyContainer
