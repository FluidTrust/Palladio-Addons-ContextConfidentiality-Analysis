/**
 */
package KAMP4attackModificationmarks.util;

import KAMP4attackModificationmarks.*;

import edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractChangePropagationStep;
import edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractModification;
import edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractModificationRepository;
import edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractSeedModifications;

import edu.kit.ipd.sdq.kamp.model.modificationmarks.ChangePropagationStep;
import org.eclipse.emf.common.notify.Adapter;
import org.eclipse.emf.common.notify.Notifier;

import org.eclipse.emf.common.notify.impl.AdapterFactoryImpl;

import org.eclipse.emf.ecore.EObject;

import org.palladiosimulator.pcm.core.entity.Entity;

/**
 * <!-- begin-user-doc -->
 * The <b>Adapter Factory</b> for the model.
 * It provides an adapter <code>createXXX</code> method for each class of the model.
 * <!-- end-user-doc -->
 * @see KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage
 * @generated
 */
public class KAMP4attackModificationmarksAdapterFactory extends AdapterFactoryImpl {
    /**
     * The cached model package.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    protected static KAMP4attackModificationmarksPackage modelPackage;

    /**
     * Creates an instance of the adapter factory.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    public KAMP4attackModificationmarksAdapterFactory() {
        if (modelPackage == null) {
            modelPackage = KAMP4attackModificationmarksPackage.eINSTANCE;
        }
    }

    /**
     * Returns whether this factory is applicable for the type of the object.
     * <!-- begin-user-doc -->
     * This implementation returns <code>true</code> if the object is either the model's package or is an instance object of the model.
     * <!-- end-user-doc -->
     * @return whether this factory is applicable for the type of the object.
     * @generated
     */
    @Override
    public boolean isFactoryForType(Object object) {
        if (object == modelPackage) {
            return true;
        }
        if (object instanceof EObject) {
            return ((EObject)object).eClass().getEPackage() == modelPackage;
        }
        return false;
    }

    /**
     * The switch that delegates to the <code>createXXX</code> methods.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @generated
     */
    protected KAMP4attackModificationmarksSwitch<Adapter> modelSwitch =
        new KAMP4attackModificationmarksSwitch<Adapter>() {
            @Override
            public <T extends KAMP4attackSeedModifications> Adapter caseAbstractKAMP4attackModificationRepository(AbstractKAMP4attackModificationRepository<T> object) {
                return createAbstractKAMP4attackModificationRepositoryAdapter();
            }
            @Override
            public Adapter caseKAMP4attackModificationRepository(KAMP4attackModificationRepository object) {
                return createKAMP4attackModificationRepositoryAdapter();
            }
            @Override
            public Adapter caseKAMP4attackSeedModifications(KAMP4attackSeedModifications object) {
                return createKAMP4attackSeedModificationsAdapter();
            }
            @Override
            public <T extends Entity> Adapter caseModifyEntity(ModifyEntity<T> object) {
                return createModifyEntityAdapter();
            }
            @Override
            public Adapter caseAttackComponent(AttackComponent object) {
                return createAttackComponentAdapter();
            }
            @Override
            public Adapter caseCredentialChange(CredentialChange object) {
                return createCredentialChangeAdapter();
            }
            @Override
            public Adapter caseCompromisedResource(CompromisedResource object) {
                return createCompromisedResourceAdapter();
            }
            @Override
            public <S extends AbstractSeedModifications, T extends AbstractChangePropagationStep> Adapter caseAbstractModificationRepository(AbstractModificationRepository<S, T> object) {
                return createAbstractModificationRepositoryAdapter();
            }
            @Override
            public Adapter caseAbstractSeedModifications(AbstractSeedModifications object) {
                return createAbstractSeedModificationsAdapter();
            }
            @Override
            public <S, T> Adapter caseAbstractModification(AbstractModification<S, T> object) {
                return createAbstractModificationAdapter();
            }
            @Override
            public Adapter caseAbstractChangePropagationStep(AbstractChangePropagationStep object) {
                return createAbstractChangePropagationStepAdapter();
            }
            @Override
            public Adapter caseChangePropagationStep(ChangePropagationStep object) {
                return createChangePropagationStepAdapter();
            }
            @Override
            public Adapter defaultCase(EObject object) {
                return createEObjectAdapter();
            }
        };

    /**
     * Creates an adapter for the <code>target</code>.
     * <!-- begin-user-doc -->
     * <!-- end-user-doc -->
     * @param target the object to adapt.
     * @return the adapter for the <code>target</code>.
     * @generated
     */
    @Override
    public Adapter createAdapter(Notifier target) {
        return modelSwitch.doSwitch((EObject)target);
    }


    /**
     * Creates a new adapter for an object of class '{@link KAMP4attackModificationmarks.AbstractKAMP4attackModificationRepository <em>Abstract KAMP 4attack Modification Repository</em>}'.
     * <!-- begin-user-doc -->
     * This default implementation returns null so that we can easily ignore cases;
     * it's useful to ignore a case when inheritance will catch all the cases anyway.
     * <!-- end-user-doc -->
     * @return the new adapter.
     * @see KAMP4attackModificationmarks.AbstractKAMP4attackModificationRepository
     * @generated
     */
    public Adapter createAbstractKAMP4attackModificationRepositoryAdapter() {
        return null;
    }

    /**
     * Creates a new adapter for an object of class '{@link KAMP4attackModificationmarks.KAMP4attackModificationRepository <em>KAMP 4attack Modification Repository</em>}'.
     * <!-- begin-user-doc -->
     * This default implementation returns null so that we can easily ignore cases;
     * it's useful to ignore a case when inheritance will catch all the cases anyway.
     * <!-- end-user-doc -->
     * @return the new adapter.
     * @see KAMP4attackModificationmarks.KAMP4attackModificationRepository
     * @generated
     */
    public Adapter createKAMP4attackModificationRepositoryAdapter() {
        return null;
    }

    /**
     * Creates a new adapter for an object of class '{@link KAMP4attackModificationmarks.KAMP4attackSeedModifications <em>KAMP 4attack Seed Modifications</em>}'.
     * <!-- begin-user-doc -->
     * This default implementation returns null so that we can easily ignore cases;
     * it's useful to ignore a case when inheritance will catch all the cases anyway.
     * <!-- end-user-doc -->
     * @return the new adapter.
     * @see KAMP4attackModificationmarks.KAMP4attackSeedModifications
     * @generated
     */
    public Adapter createKAMP4attackSeedModificationsAdapter() {
        return null;
    }

    /**
     * Creates a new adapter for an object of class '{@link KAMP4attackModificationmarks.ModifyEntity <em>Modify Entity</em>}'.
     * <!-- begin-user-doc -->
     * This default implementation returns null so that we can easily ignore cases;
     * it's useful to ignore a case when inheritance will catch all the cases anyway.
     * <!-- end-user-doc -->
     * @return the new adapter.
     * @see KAMP4attackModificationmarks.ModifyEntity
     * @generated
     */
    public Adapter createModifyEntityAdapter() {
        return null;
    }

    /**
     * Creates a new adapter for an object of class '{@link KAMP4attackModificationmarks.AttackComponent <em>Attack Component</em>}'.
     * <!-- begin-user-doc -->
     * This default implementation returns null so that we can easily ignore cases;
     * it's useful to ignore a case when inheritance will catch all the cases anyway.
     * <!-- end-user-doc -->
     * @return the new adapter.
     * @see KAMP4attackModificationmarks.AttackComponent
     * @generated
     */
    public Adapter createAttackComponentAdapter() {
        return null;
    }

    /**
     * Creates a new adapter for an object of class '{@link KAMP4attackModificationmarks.CredentialChange <em>Credential Change</em>}'.
     * <!-- begin-user-doc -->
     * This default implementation returns null so that we can easily ignore cases;
     * it's useful to ignore a case when inheritance will catch all the cases anyway.
     * <!-- end-user-doc -->
     * @return the new adapter.
     * @see KAMP4attackModificationmarks.CredentialChange
     * @generated
     */
    public Adapter createCredentialChangeAdapter() {
        return null;
    }

    /**
     * Creates a new adapter for an object of class '{@link KAMP4attackModificationmarks.CompromisedResource <em>Compromised Resource</em>}'.
     * <!-- begin-user-doc -->
     * This default implementation returns null so that we can easily ignore cases;
     * it's useful to ignore a case when inheritance will catch all the cases anyway.
     * <!-- end-user-doc -->
     * @return the new adapter.
     * @see KAMP4attackModificationmarks.CompromisedResource
     * @generated
     */
    public Adapter createCompromisedResourceAdapter() {
        return null;
    }

    /**
     * Creates a new adapter for an object of class '{@link edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractModificationRepository <em>Abstract Modification Repository</em>}'.
     * <!-- begin-user-doc -->
     * This default implementation returns null so that we can easily ignore cases;
     * it's useful to ignore a case when inheritance will catch all the cases anyway.
     * <!-- end-user-doc -->
     * @return the new adapter.
     * @see edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractModificationRepository
     * @generated
     */
    public Adapter createAbstractModificationRepositoryAdapter() {
        return null;
    }

    /**
     * Creates a new adapter for an object of class '{@link edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractSeedModifications <em>Abstract Seed Modifications</em>}'.
     * <!-- begin-user-doc -->
     * This default implementation returns null so that we can easily ignore cases;
     * it's useful to ignore a case when inheritance will catch all the cases anyway.
     * <!-- end-user-doc -->
     * @return the new adapter.
     * @see edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractSeedModifications
     * @generated
     */
    public Adapter createAbstractSeedModificationsAdapter() {
        return null;
    }

    /**
     * Creates a new adapter for an object of class '{@link edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractModification <em>Abstract Modification</em>}'.
     * <!-- begin-user-doc -->
     * This default implementation returns null so that we can easily ignore cases;
     * it's useful to ignore a case when inheritance will catch all the cases anyway.
     * <!-- end-user-doc -->
     * @return the new adapter.
     * @see edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractModification
     * @generated
     */
    public Adapter createAbstractModificationAdapter() {
        return null;
    }

    /**
     * Creates a new adapter for an object of class '{@link edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractChangePropagationStep <em>Abstract Change Propagation Step</em>}'.
     * <!-- begin-user-doc -->
     * This default implementation returns null so that we can easily ignore cases;
     * it's useful to ignore a case when inheritance will catch all the cases anyway.
     * <!-- end-user-doc -->
     * @return the new adapter.
     * @see edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractChangePropagationStep
     * @generated
     */
    public Adapter createAbstractChangePropagationStepAdapter() {
        return null;
    }

    /**
     * Creates a new adapter for an object of class '{@link edu.kit.ipd.sdq.kamp.model.modificationmarks.ChangePropagationStep <em>Change Propagation Step</em>}'.
     * <!-- begin-user-doc -->
     * This default implementation returns null so that we can easily ignore cases;
     * it's useful to ignore a case when inheritance will catch all the cases anyway.
     * <!-- end-user-doc -->
     * @return the new adapter.
     * @see edu.kit.ipd.sdq.kamp.model.modificationmarks.ChangePropagationStep
     * @generated
     */
    public Adapter createChangePropagationStepAdapter() {
        return null;
    }

    /**
     * Creates a new adapter for the default case.
     * <!-- begin-user-doc -->
     * This default implementation returns null.
     * <!-- end-user-doc -->
     * @return the new adapter.
     * @generated
     */
    public Adapter createEObjectAdapter() {
        return null;
    }

} //KAMP4attackModificationmarksAdapterFactory
