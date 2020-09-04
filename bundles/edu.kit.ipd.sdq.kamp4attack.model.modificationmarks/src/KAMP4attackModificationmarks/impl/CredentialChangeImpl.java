/**
 */
package KAMP4attackModificationmarks.impl;

import KAMP4attackModificationmarks.CompromisedResource;
import KAMP4attackModificationmarks.CredentialChange;
import KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;

import edu.kit.ipd.sdq.kamp.model.modificationmarks.impl.ChangePropagationStepImpl;

import java.util.Collection;

import org.eclipse.emf.common.notify.NotificationChain;

import org.eclipse.emf.common.util.EList;

import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.InternalEObject;

import org.eclipse.emf.ecore.util.EObjectContainmentEList;
import org.eclipse.emf.ecore.util.InternalEList;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Credential Change</b></em>'.
 * <!-- end-user-doc -->
 * <p>
 * The following features are implemented:
 * </p>
 * <ul>
 *   <li>{@link KAMP4attackModificationmarks.impl.CredentialChangeImpl#getCompromisedresource <em>Compromisedresource</em>}</li>
 * </ul>
 *
 * @generated
 */
public class CredentialChangeImpl extends ChangePropagationStepImpl implements CredentialChange {
    /**
     * The cached value of the '{@link #getCompromisedresource() <em>Compromisedresource</em>}' containment reference list.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @see #getCompromisedresource()
     * @generated
     * @ordered
     */
    protected EList<CompromisedResource> compromisedresource;

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    protected CredentialChangeImpl() {
        super();
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    @Override
    protected EClass eStaticClass() {
        return KAMP4attackModificationmarksPackage.Literals.CREDENTIAL_CHANGE;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    public EList<CompromisedResource> getCompromisedresource() {
        if (compromisedresource == null) {
            compromisedresource = new EObjectContainmentEList<CompromisedResource>(CompromisedResource.class, this, KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE);
        }
        return compromisedresource;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    @Override
    public NotificationChain eInverseRemove(InternalEObject otherEnd, int featureID, NotificationChain msgs) {
        switch (featureID) {
            case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE:
                return ((InternalEList<?>)getCompromisedresource()).basicRemove(otherEnd, msgs);
        }
        return super.eInverseRemove(otherEnd, featureID, msgs);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    @Override
    public Object eGet(int featureID, boolean resolve, boolean coreType) {
        switch (featureID) {
            case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE:
                return getCompromisedresource();
        }
        return super.eGet(featureID, resolve, coreType);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    @SuppressWarnings("unchecked")
    @Override
    public void eSet(int featureID, Object newValue) {
        switch (featureID) {
            case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE:
                getCompromisedresource().clear();
                getCompromisedresource().addAll((Collection<? extends CompromisedResource>)newValue);
                return;
        }
        super.eSet(featureID, newValue);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    @Override
    public void eUnset(int featureID) {
        switch (featureID) {
            case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE:
                getCompromisedresource().clear();
                return;
        }
        super.eUnset(featureID);
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    @Override
    public boolean eIsSet(int featureID) {
        switch (featureID) {
            case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE__COMPROMISEDRESOURCE:
                return compromisedresource != null && !compromisedresource.isEmpty();
        }
        return super.eIsSet(featureID);
    }

} //CredentialChangeImpl
