/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.*;

import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.EPackage;

import org.eclipse.emf.ecore.impl.EFactoryImpl;

import org.eclipse.emf.ecore.plugin.EcorePlugin;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model <b>Factory</b>.
 * <!-- end-user-doc -->
 * @generated
 */
public class KAMP4attackModificationmarksFactoryImpl extends EFactoryImpl implements KAMP4attackModificationmarksFactory {
    /**
     * Creates the default factory implementation.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    public static KAMP4attackModificationmarksFactory init() {
        try {
            KAMP4attackModificationmarksFactory theKAMP4attackModificationmarksFactory = (KAMP4attackModificationmarksFactory)EPackage.Registry.INSTANCE.getEFactory(KAMP4attackModificationmarksPackage.eNS_URI);
            if (theKAMP4attackModificationmarksFactory != null) {
                return theKAMP4attackModificationmarksFactory;
            }
        }
        catch (Exception exception) {
            EcorePlugin.INSTANCE.log(exception);
        }
        return new KAMP4attackModificationmarksFactoryImpl();
    }

    /**
     * Creates an instance of the factory.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    public KAMP4attackModificationmarksFactoryImpl() {
        super();
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    @Override
    public EObject create(EClass eClass) {
        switch (eClass.getClassifierID()) {
            case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY: return createKAMP4attackModificationRepository();
            case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_SEED_MODIFICATIONS: return createKAMP4attackSeedModifications();
            case KAMP4attackModificationmarksPackage.ATTACK_COMPONENT: return createAttackComponent();
            case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE: return createCredentialChange();
            case KAMP4attackModificationmarksPackage.COMPROMISED_RESOURCE: return createCompromisedResource();
            case KAMP4attackModificationmarksPackage.COMPROMISED_ASSEMBLY: return createCompromisedAssembly();
            case KAMP4attackModificationmarksPackage.CONTEXT_CHANGE: return createContextChange();
            default:
                throw new IllegalArgumentException("The class '" + eClass.getName() + "' is not a valid classifier");
        }
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    public KAMP4attackModificationRepository createKAMP4attackModificationRepository() {
        KAMP4attackModificationRepositoryImpl kamp4attackModificationRepository = new KAMP4attackModificationRepositoryImpl();
        return kamp4attackModificationRepository;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    public KAMP4attackSeedModifications createKAMP4attackSeedModifications() {
        KAMP4attackSeedModificationsImpl kamp4attackSeedModifications = new KAMP4attackSeedModificationsImpl();
        return kamp4attackSeedModifications;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    public AttackComponent createAttackComponent() {
        AttackComponentImpl attackComponent = new AttackComponentImpl();
        return attackComponent;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    public CredentialChange createCredentialChange() {
        CredentialChangeImpl credentialChange = new CredentialChangeImpl();
        return credentialChange;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    public CompromisedResource createCompromisedResource() {
        CompromisedResourceImpl compromisedResource = new CompromisedResourceImpl();
        return compromisedResource;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    public CompromisedAssembly createCompromisedAssembly() {
        CompromisedAssemblyImpl compromisedAssembly = new CompromisedAssemblyImpl();
        return compromisedAssembly;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    public ContextChange createContextChange() {
        ContextChangeImpl contextChange = new ContextChangeImpl();
        return contextChange;
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    public KAMP4attackModificationmarksPackage getKAMP4attackModificationmarksPackage() {
        return (KAMP4attackModificationmarksPackage)getEPackage();
    }

    /**
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @deprecated
     * @generated
     */
    @Deprecated
    public static KAMP4attackModificationmarksPackage getPackage() {
        return KAMP4attackModificationmarksPackage.eINSTANCE;
    }

} //KAMP4attackModificationmarksFactoryImpl
