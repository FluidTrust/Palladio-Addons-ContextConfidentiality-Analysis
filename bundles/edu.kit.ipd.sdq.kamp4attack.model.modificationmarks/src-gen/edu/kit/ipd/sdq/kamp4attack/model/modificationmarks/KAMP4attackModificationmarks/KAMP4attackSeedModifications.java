/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks;

import edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractSeedModifications;

import org.eclipse.emf.common.util.EList;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>KAMP 4attack Seed Modifications</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackSeedModifications#getAttackcomponent <em>Attackcomponent</em>}</li>
 * </ul>
 *
 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getKAMP4attackSeedModifications()
 * @model
 * @generated
 */
public interface KAMP4attackSeedModifications extends AbstractSeedModifications
{
	/**
	 * Returns the value of the '<em><b>Attackcomponent</b></em>' containment reference list.
	 * The list contents are of type {@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AttackerSelection}.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Attackcomponent</em>' containment reference list.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getKAMP4attackSeedModifications_Attackcomponent()
	 * @model containment="true"
	 * @generated
	 */
	EList<AttackerSelection> getAttackcomponent();

} // KAMP4attackSeedModifications
