/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.util;

import edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractChangePropagationStep;
import edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractModification;
import edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractModificationRepository;
import edu.kit.ipd.sdq.kamp.model.modificationmarks.AbstractSeedModifications;
import edu.kit.ipd.sdq.kamp.model.modificationmarks.ChangePropagationStep;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.*;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.EPackage;

import org.eclipse.emf.ecore.util.Switch;

import org.palladiosimulator.pcm.core.entity.Entity;

/**
 * <!-- begin-user-doc -->
 * The <b>Switch</b> for the model's inheritance hierarchy.
 * It supports the call {@link #doSwitch(EObject) doSwitch(object)}
 * to invoke the <code>caseXXX</code> method for each class of the model,
 * starting with the actual class of the object
 * and proceeding up the inheritance hierarchy
 * until a non-null result is returned,
 * which is the result of the switch.
 * <!-- end-user-doc -->
 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage
 * @generated
 */
public class KAMP4attackModificationmarksSwitch<T1> extends Switch<T1>
{
	/**
	 * The cached model package
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected static KAMP4attackModificationmarksPackage modelPackage;

	/**
	 * Creates an instance of the switch.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public KAMP4attackModificationmarksSwitch()
	{
		if (modelPackage == null)
		{
			modelPackage = KAMP4attackModificationmarksPackage.eINSTANCE;
		}
	}

	/**
	 * Checks whether this is a switch for the given package.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @param ePackage the package in question.
	 * @return whether this is a switch for the given package.
	 * @generated
	 */
	@Override
	protected boolean isSwitchFor(EPackage ePackage)
	{
		return ePackage == modelPackage;
	}

	/**
	 * Calls <code>caseXXX</code> for each class of the model until one returns a non null result; it yields that result.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the first non-null result returned by a <code>caseXXX</code> call.
	 * @generated
	 */
	@Override
	protected T1 doSwitch(int classifierID, EObject theEObject)
	{
		switch (classifierID)
		{
			case KAMP4attackModificationmarksPackage.ABSTRACT_KAMP_4ATTACK_MODIFICATION_REPOSITORY:
			{
				AbstractKAMP4attackModificationRepository<?> abstractKAMP4attackModificationRepository = (AbstractKAMP4attackModificationRepository<?>)theEObject;
				T1 result = caseAbstractKAMP4attackModificationRepository(abstractKAMP4attackModificationRepository);
				if (result == null) result = caseAbstractModificationRepository(abstractKAMP4attackModificationRepository);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_MODIFICATION_REPOSITORY:
			{
				KAMP4attackModificationRepository kamp4attackModificationRepository = (KAMP4attackModificationRepository)theEObject;
				T1 result = caseKAMP4attackModificationRepository(kamp4attackModificationRepository);
				if (result == null) result = caseAbstractKAMP4attackModificationRepository(kamp4attackModificationRepository);
				if (result == null) result = caseAbstractModificationRepository(kamp4attackModificationRepository);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			case KAMP4attackModificationmarksPackage.KAMP_4ATTACK_SEED_MODIFICATIONS:
			{
				KAMP4attackSeedModifications kamp4attackSeedModifications = (KAMP4attackSeedModifications)theEObject;
				T1 result = caseKAMP4attackSeedModifications(kamp4attackSeedModifications);
				if (result == null) result = caseAbstractSeedModifications(kamp4attackSeedModifications);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			case KAMP4attackModificationmarksPackage.MODIFY_ENTITY:
			{
				ModifyEntity<?> modifyEntity = (ModifyEntity<?>)theEObject;
				T1 result = caseModifyEntity(modifyEntity);
				if (result == null) result = caseAbstractModification(modifyEntity);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			case KAMP4attackModificationmarksPackage.ATTACKER_SELECTION:
			{
				AttackerSelection attackerSelection = (AttackerSelection)theEObject;
				T1 result = caseAttackerSelection(attackerSelection);
				if (result == null) result = caseModifyEntity(attackerSelection);
				if (result == null) result = caseAbstractModification(attackerSelection);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			case KAMP4attackModificationmarksPackage.CREDENTIAL_CHANGE:
			{
				CredentialChange credentialChange = (CredentialChange)theEObject;
				T1 result = caseCredentialChange(credentialChange);
				if (result == null) result = caseChangePropagationStep(credentialChange);
				if (result == null) result = caseAbstractChangePropagationStep(credentialChange);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			case KAMP4attackModificationmarksPackage.COMPROMISED_RESOURCE:
			{
				CompromisedResource compromisedResource = (CompromisedResource)theEObject;
				T1 result = caseCompromisedResource(compromisedResource);
				if (result == null) result = caseModifyEntity(compromisedResource);
				if (result == null) result = caseAbstractModification(compromisedResource);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			case KAMP4attackModificationmarksPackage.COMPROMISED_ASSEMBLY:
			{
				CompromisedAssembly compromisedAssembly = (CompromisedAssembly)theEObject;
				T1 result = caseCompromisedAssembly(compromisedAssembly);
				if (result == null) result = caseModifyEntity(compromisedAssembly);
				if (result == null) result = caseAbstractModification(compromisedAssembly);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			case KAMP4attackModificationmarksPackage.CONTEXT_CHANGE:
			{
				ContextChange contextChange = (ContextChange)theEObject;
				T1 result = caseContextChange(contextChange);
				if (result == null) result = caseModifyEntity(contextChange);
				if (result == null) result = caseAbstractModification(contextChange);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			case KAMP4attackModificationmarksPackage.COMPROMISED_LINKING_RESOURCE:
			{
				CompromisedLinkingResource compromisedLinkingResource = (CompromisedLinkingResource)theEObject;
				T1 result = caseCompromisedLinkingResource(compromisedLinkingResource);
				if (result == null) result = caseModifyEntity(compromisedLinkingResource);
				if (result == null) result = caseAbstractModification(compromisedLinkingResource);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			case KAMP4attackModificationmarksPackage.COMPROMISED_SERVICE:
			{
				CompromisedService compromisedService = (CompromisedService)theEObject;
				T1 result = caseCompromisedService(compromisedService);
				if (result == null) result = caseModifyEntity(compromisedService);
				if (result == null) result = caseAbstractModification(compromisedService);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			case KAMP4attackModificationmarksPackage.SERVICE_RESTRICTION_CONTAINER:
			{
				ServiceRestrictionContainer serviceRestrictionContainer = (ServiceRestrictionContainer)theEObject;
				T1 result = caseServiceRestrictionContainer(serviceRestrictionContainer);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			case KAMP4attackModificationmarksPackage.COMPROMISED_DATA:
			{
				CompromisedData compromisedData = (CompromisedData)theEObject;
				T1 result = caseCompromisedData(compromisedData);
				if (result == null) result = caseModifyEntity(compromisedData);
				if (result == null) result = caseAbstractModification(compromisedData);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			case KAMP4attackModificationmarksPackage.DATAMODEL_CONTAINER:
			{
				DatamodelContainer datamodelContainer = (DatamodelContainer)theEObject;
				T1 result = caseDatamodelContainer(datamodelContainer);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			case KAMP4attackModificationmarksPackage.ASSEMBLY_CONTEXT_DETAIL_CONTAINER:
			{
				AssemblyContextDetailContainer assemblyContextDetailContainer = (AssemblyContextDetailContainer)theEObject;
				T1 result = caseAssemblyContextDetailContainer(assemblyContextDetailContainer);
				if (result == null) result = defaultCase(theEObject);
				return result;
			}
			default: return defaultCase(theEObject);
		}
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Abstract KAMP 4attack Modification Repository</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Abstract KAMP 4attack Modification Repository</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public <T extends KAMP4attackSeedModifications> T1 caseAbstractKAMP4attackModificationRepository(AbstractKAMP4attackModificationRepository<T> object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>KAMP 4attack Modification Repository</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>KAMP 4attack Modification Repository</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseKAMP4attackModificationRepository(KAMP4attackModificationRepository object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>KAMP 4attack Seed Modifications</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>KAMP 4attack Seed Modifications</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseKAMP4attackSeedModifications(KAMP4attackSeedModifications object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Modify Entity</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Modify Entity</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public <T extends Entity> T1 caseModifyEntity(ModifyEntity<T> object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Attacker Selection</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Attacker Selection</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseAttackerSelection(AttackerSelection object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Credential Change</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Credential Change</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseCredentialChange(CredentialChange object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Compromised Resource</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Compromised Resource</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseCompromisedResource(CompromisedResource object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Compromised Assembly</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Compromised Assembly</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseCompromisedAssembly(CompromisedAssembly object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Context Change</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Context Change</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseContextChange(ContextChange object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Compromised Linking Resource</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Compromised Linking Resource</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseCompromisedLinkingResource(CompromisedLinkingResource object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Compromised Service</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Compromised Service</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseCompromisedService(CompromisedService object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Service Restriction Container</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Service Restriction Container</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseServiceRestrictionContainer(ServiceRestrictionContainer object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Compromised Data</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Compromised Data</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseCompromisedData(CompromisedData object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Datamodel Container</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Datamodel Container</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseDatamodelContainer(DatamodelContainer object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Assembly Context Detail Container</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Assembly Context Detail Container</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseAssemblyContextDetailContainer(AssemblyContextDetailContainer object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Abstract Modification Repository</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Abstract Modification Repository</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public <S extends AbstractSeedModifications, T extends AbstractChangePropagationStep> T1 caseAbstractModificationRepository(AbstractModificationRepository<S, T> object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Abstract Seed Modifications</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Abstract Seed Modifications</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseAbstractSeedModifications(AbstractSeedModifications object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Abstract Modification</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Abstract Modification</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public <S, T> T1 caseAbstractModification(AbstractModification<S, T> object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Abstract Change Propagation Step</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Abstract Change Propagation Step</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseAbstractChangePropagationStep(AbstractChangePropagationStep object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>Change Propagation Step</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>Change Propagation Step</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject) doSwitch(EObject)
	 * @generated
	 */
	public T1 caseChangePropagationStep(ChangePropagationStep object)
	{
		return null;
	}

	/**
	 * Returns the result of interpreting the object as an instance of '<em>EObject</em>'.
	 * <!-- begin-user-doc -->
	 * This implementation returns null;
	 * returning a non-null result will terminate the switch, but this is the last case anyway.
	 * <!-- end-user-doc -->
	 * @param object the target of the switch.
	 * @return the result of interpreting the object as an instance of '<em>EObject</em>'.
	 * @see #doSwitch(org.eclipse.emf.ecore.EObject)
	 * @generated
	 */
	@Override
	public T1 defaultCase(EObject object)
	{
		return null;
	}

} //KAMP4attackModificationmarksSwitch
