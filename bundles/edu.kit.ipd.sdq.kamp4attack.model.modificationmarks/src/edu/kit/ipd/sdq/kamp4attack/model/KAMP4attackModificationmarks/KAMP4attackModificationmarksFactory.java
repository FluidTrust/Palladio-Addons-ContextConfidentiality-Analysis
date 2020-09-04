/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.KAMP4attackModificationmarks;

import org.eclipse.emf.ecore.EFactory;

/**
 * <!-- begin-user-doc -->
 * The <b>Factory</b> for the model.
 * It provides a create method for each non-abstract class of the model.
 * <!-- end-user-doc -->
 * @see edu.kit.ipd.sdq.kamp4attack.model.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage
 * @generated
 */
public interface KAMP4attackModificationmarksFactory extends EFactory {
    /**
     * The singleton instance of the factory.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    KAMP4attackModificationmarksFactory eINSTANCE = edu.kit.ipd.sdq.kamp4attack.model.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksFactoryImpl.init();

    /**
     * Returns a new object of class '<em>KAMP 4attack Modification Repository</em>'.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return a new object of class '<em>KAMP 4attack Modification Repository</em>'.
     * @generated
     */
    KAMP4attackModificationRepository createKAMP4attackModificationRepository();

    /**
     * Returns a new object of class '<em>KAMP 4attack Seed Modifications</em>'.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return a new object of class '<em>KAMP 4attack Seed Modifications</em>'.
     * @generated
     */
    KAMP4attackSeedModifications createKAMP4attackSeedModifications();

    /**
     * Returns a new object of class '<em>Attack Component</em>'.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return a new object of class '<em>Attack Component</em>'.
     * @generated
     */
    AttackComponent createAttackComponent();

    /**
     * Returns the package supported by this factory.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the package supported by this factory.
     * @generated
     */
    KAMP4attackModificationmarksPackage getKAMP4attackModificationmarksPackage();

} //KAMP4attackModificationmarksFactory
