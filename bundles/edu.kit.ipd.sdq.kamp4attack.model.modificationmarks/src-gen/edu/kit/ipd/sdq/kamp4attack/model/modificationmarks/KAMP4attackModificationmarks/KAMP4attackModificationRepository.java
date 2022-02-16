/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks;

import org.eclipse.emf.cdo.CDOObject;

import org.eclipse.emf.common.util.EList;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>KAMP 4attack Modification Repository</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationRepository#getChangePropagationSteps <em>Change Propagation Steps</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationRepository#getSeedModifications <em>Seed Modifications</em>}</li>
 * </ul>
 *
 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getKAMP4attackModificationRepository()
 * @model
 * @extends CDOObject
 * @generated
 */
public interface KAMP4attackModificationRepository extends CDOObject
{
	/**
	 * Returns the value of the '<em><b>Change Propagation Steps</b></em>' containment reference list.
	 * The list contents are of type {@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange}.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Change Propagation Steps</em>' containment reference list.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getKAMP4attackModificationRepository_ChangePropagationSteps()
	 * @model containment="true"
	 * @generated
	 */
	EList<CredentialChange> getChangePropagationSteps();

	/**
	 * Returns the value of the '<em><b>Seed Modifications</b></em>' containment reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Seed Modifications</em>' containment reference.
	 * @see #setSeedModifications(KAMP4attackSeedModifications)
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getKAMP4attackModificationRepository_SeedModifications()
	 * @model containment="true" required="true"
	 * @generated
	 */
	KAMP4attackSeedModifications getSeedModifications();

	/**
	 * Sets the value of the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationRepository#getSeedModifications <em>Seed Modifications</em>}' containment reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @param value the new value of the '<em>Seed Modifications</em>' containment reference.
	 * @see #getSeedModifications()
	 * @generated
	 */
	void setSeedModifications(KAMP4attackSeedModifications value);

} // KAMP4attackModificationRepository
