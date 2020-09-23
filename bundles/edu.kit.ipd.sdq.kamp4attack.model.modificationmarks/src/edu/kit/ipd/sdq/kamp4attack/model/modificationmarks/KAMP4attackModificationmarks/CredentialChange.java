/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks;

import edu.kit.ipd.sdq.kamp.model.modificationmarks.ChangePropagationStep;
import org.eclipse.emf.common.util.EList;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Credential Change</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getCompromisedresource <em>Compromisedresource</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getCompromisedassembly <em>Compromisedassembly</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getContextchange <em>Contextchange</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#isChanged <em>Changed</em>}</li>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getCompromisedlinkingresource <em>Compromisedlinkingresource</em>}</li>
 * </ul>
 *
 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getCredentialChange()
 * @model
 * @generated
 */
public interface CredentialChange extends ChangePropagationStep {
    /**
     * Returns the value of the '<em><b>Compromisedresource</b></em>' containment reference list.
     * The list contents are of type {@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource}.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the value of the '<em>Compromisedresource</em>' containment reference list.
     * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getCredentialChange_Compromisedresource()
     * @model containment="true"
     * @generated
     */
    EList<CompromisedResource> getCompromisedresource();

    /**
     * Returns the value of the '<em><b>Compromisedassembly</b></em>' containment reference list.
     * The list contents are of type {@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly}.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the value of the '<em>Compromisedassembly</em>' containment reference list.
     * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getCredentialChange_Compromisedassembly()
     * @model containment="true"
     * @generated
     */
    EList<CompromisedAssembly> getCompromisedassembly();

    /**
     * Returns the value of the '<em><b>Contextchange</b></em>' containment reference list.
     * The list contents are of type {@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange}.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the value of the '<em>Contextchange</em>' containment reference list.
     * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getCredentialChange_Contextchange()
     * @model containment="true"
     * @generated
     */
    EList<ContextChange> getContextchange();

    /**
     * Returns the value of the '<em><b>Changed</b></em>' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the value of the '<em>Changed</em>' attribute.
     * @see #setChanged(boolean)
     * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getCredentialChange_Changed()
     * @model
     * @generated
     */
    boolean isChanged();

    /**
     * Sets the value of the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#isChanged <em>Changed</em>}' attribute.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @param value the new value of the '<em>Changed</em>' attribute.
     * @see #isChanged()
     * @generated
     */
    void setChanged(boolean value);

    /**
     * Returns the value of the '<em><b>Compromisedlinkingresource</b></em>' containment reference list.
     * The list contents are of type {@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource}.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the value of the '<em>Compromisedlinkingresource</em>' containment reference list.
     * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getCredentialChange_Compromisedlinkingresource()
     * @model containment="true"
     * @generated
     */
    EList<CompromisedLinkingResource> getCompromisedlinkingresource();

} // CredentialChange
