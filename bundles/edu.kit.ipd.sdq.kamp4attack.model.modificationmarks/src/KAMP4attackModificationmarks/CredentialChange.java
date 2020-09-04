/**
 */
package KAMP4attackModificationmarks;

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
 *   <li>{@link KAMP4attackModificationmarks.CredentialChange#getCompromisedresource <em>Compromisedresource</em>}</li>
 * </ul>
 *
 * @see KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getCredentialChange()
 * @model
 * @generated
 */
public interface CredentialChange extends ChangePropagationStep {
    /**
     * Returns the value of the '<em><b>Compromisedresource</b></em>' containment reference list.
     * The list contents are of type {@link KAMP4attackModificationmarks.CompromisedResource}.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @return the value of the '<em>Compromisedresource</em>' containment reference list.
     * @see KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getCredentialChange_Compromisedresource()
     * @model containment="true"
     * @generated
     */
    EList<CompromisedResource> getCompromisedresource();

} // CredentialChange
