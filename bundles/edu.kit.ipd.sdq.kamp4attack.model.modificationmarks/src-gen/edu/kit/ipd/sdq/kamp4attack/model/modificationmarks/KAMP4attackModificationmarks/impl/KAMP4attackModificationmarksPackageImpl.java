/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl;

import de.uka.ipd.sdq.identifier.IdentifierPackage;

import de.uka.ipd.sdq.probfunction.ProbfunctionPackage;

import de.uka.ipd.sdq.stoex.StoexPackage;

import de.uka.ipd.sdq.units.UnitsPackage;

import edu.kit.ipd.sdq.kamp.model.modificationmarks.ModificationmarksPackage;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AbstractKAMP4attackModificationRepository;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AttackerSelection;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedData;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedService;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.DatamodelContainer;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationRepository;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackSeedModifications;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ModifyEntity;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ServiceRestrictionContainer;

import org.eclipse.emf.ecore.EAttribute;
import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.EGenericType;
import org.eclipse.emf.ecore.EPackage;
import org.eclipse.emf.ecore.EReference;
import org.eclipse.emf.ecore.ETypeParameter;
import org.eclipse.emf.ecore.EcorePackage;

import org.eclipse.emf.ecore.impl.EPackageImpl;

import org.palladiosimulator.pcm.PcmPackage;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerPackage;

import org.palladiosimulator.pcm.confidentiality.context.ContextPackage;

import org.palladiosimulator.pcm.confidentiality.context.system.SystemPackage;

import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.StructurePackage;

import org.palladiosimulator.pcm.core.composition.CompositionPackage;

import org.palladiosimulator.pcm.core.entity.EntityPackage;

import org.palladiosimulator.pcm.resourceenvironment.ResourceenvironmentPackage;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model <b>Package</b>.
 * <!-- end-user-doc -->
 * @generated
 */
public class KAMP4attackModificationmarksPackageImpl extends EPackageImpl implements KAMP4attackModificationmarksPackage
{
	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private EClass abstractKAMP4attackModificationRepositoryEClass = null;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private EClass kamp4attackModificationRepositoryEClass = null;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private EClass kamp4attackSeedModificationsEClass = null;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private EClass modifyEntityEClass = null;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private EClass attackerSelectionEClass = null;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private EClass credentialChangeEClass = null;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private EClass compromisedResourceEClass = null;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private EClass compromisedAssemblyEClass = null;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private EClass contextChangeEClass = null;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private EClass compromisedLinkingResourceEClass = null;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private EClass compromisedServiceEClass = null;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private EClass serviceRestrictionContainerEClass = null;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private EClass compromisedDataEClass = null;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private EClass datamodelContainerEClass = null;

	/**
	 * Creates an instance of the model <b>Package</b>, registered with
	 * {@link org.eclipse.emf.ecore.EPackage.Registry EPackage.Registry} by the package
	 * package URI value.
	 * <p>Note: the correct way to create the package is via the static
	 * factory method {@link #init init()}, which also performs
	 * initialization of the package, or returns the registered package,
	 * if one already exists.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see org.eclipse.emf.ecore.EPackage.Registry
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#eNS_URI
	 * @see #init()
	 * @generated
	 */
	private KAMP4attackModificationmarksPackageImpl()
	{
		super(eNS_URI, KAMP4attackModificationmarksFactory.eINSTANCE);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private static boolean isInited = false;

	/**
	 * Creates, registers, and initializes the <b>Package</b> for this model, and for any others upon which it depends.
	 *
	 * <p>This method is used to initialize {@link KAMP4attackModificationmarksPackage#eINSTANCE} when that field is accessed.
	 * Clients should not invoke it directly. Instead, they should simply access that field to obtain the package.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #eNS_URI
	 * @see #createPackageContents()
	 * @see #initializePackageContents()
	 * @generated
	 */
	public static KAMP4attackModificationmarksPackage init()
	{
		if (isInited) return (KAMP4attackModificationmarksPackage)EPackage.Registry.INSTANCE.getEPackage(KAMP4attackModificationmarksPackage.eNS_URI);

		// Obtain or create and register package
		Object registeredKAMP4attackModificationmarksPackage = EPackage.Registry.INSTANCE.get(eNS_URI);
		KAMP4attackModificationmarksPackageImpl theKAMP4attackModificationmarksPackage = registeredKAMP4attackModificationmarksPackage instanceof KAMP4attackModificationmarksPackageImpl ? (KAMP4attackModificationmarksPackageImpl)registeredKAMP4attackModificationmarksPackage : new KAMP4attackModificationmarksPackageImpl();

		isInited = true;

		// Initialize simple dependencies
		AttackerPackage.eINSTANCE.eClass();
		ContextPackage.eINSTANCE.eClass();
		EcorePackage.eINSTANCE.eClass();
		IdentifierPackage.eINSTANCE.eClass();
		ModificationmarksPackage.eINSTANCE.eClass();
		PcmPackage.eINSTANCE.eClass();
		ProbfunctionPackage.eINSTANCE.eClass();
		StoexPackage.eINSTANCE.eClass();
		UnitsPackage.eINSTANCE.eClass();

		// Create package meta-data objects
		theKAMP4attackModificationmarksPackage.createPackageContents();

		// Initialize created meta-data
		theKAMP4attackModificationmarksPackage.initializePackageContents();

		// Mark meta-data to indicate it can't be changed
		theKAMP4attackModificationmarksPackage.freeze();

		// Update the registry and return the package
		EPackage.Registry.INSTANCE.put(KAMP4attackModificationmarksPackage.eNS_URI, theKAMP4attackModificationmarksPackage);
		return theKAMP4attackModificationmarksPackage;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EClass getAbstractKAMP4attackModificationRepository()
	{
		return abstractKAMP4attackModificationRepositoryEClass;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EClass getKAMP4attackModificationRepository()
	{
		return kamp4attackModificationRepositoryEClass;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EClass getKAMP4attackSeedModifications()
	{
		return kamp4attackSeedModificationsEClass;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EReference getKAMP4attackSeedModifications_Attackcomponent()
	{
		return (EReference)kamp4attackSeedModificationsEClass.getEStructuralFeatures().get(0);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EClass getModifyEntity()
	{
		return modifyEntityEClass;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EClass getAttackerSelection()
	{
		return attackerSelectionEClass;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EClass getCredentialChange()
	{
		return credentialChangeEClass;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EReference getCredentialChange_Compromisedresource()
	{
		return (EReference)credentialChangeEClass.getEStructuralFeatures().get(0);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EReference getCredentialChange_Compromisedassembly()
	{
		return (EReference)credentialChangeEClass.getEStructuralFeatures().get(1);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EReference getCredentialChange_Contextchange()
	{
		return (EReference)credentialChangeEClass.getEStructuralFeatures().get(2);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EAttribute getCredentialChange_Changed()
	{
		return (EAttribute)credentialChangeEClass.getEStructuralFeatures().get(3);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EReference getCredentialChange_Compromisedlinkingresource()
	{
		return (EReference)credentialChangeEClass.getEStructuralFeatures().get(4);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EReference getCredentialChange_Compromisedservice()
	{
		return (EReference)credentialChangeEClass.getEStructuralFeatures().get(5);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EReference getCredentialChange_Servicerestrictioncontainer()
	{
		return (EReference)credentialChangeEClass.getEStructuralFeatures().get(6);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EReference getCredentialChange_Compromiseddata()
	{
		return (EReference)credentialChangeEClass.getEStructuralFeatures().get(7);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EReference getCredentialChange_Datamodelcontainer()
	{
		return (EReference)credentialChangeEClass.getEStructuralFeatures().get(8);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EClass getCompromisedResource()
	{
		return compromisedResourceEClass;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EClass getCompromisedAssembly()
	{
		return compromisedAssemblyEClass;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EClass getContextChange()
	{
		return contextChangeEClass;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EClass getCompromisedLinkingResource()
	{
		return compromisedLinkingResourceEClass;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EClass getCompromisedService()
	{
		return compromisedServiceEClass;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EClass getServiceRestrictionContainer()
	{
		return serviceRestrictionContainerEClass;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EReference getServiceRestrictionContainer_Servicerestriction()
	{
		return (EReference)serviceRestrictionContainerEClass.getEStructuralFeatures().get(0);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EClass getCompromisedData()
	{
		return compromisedDataEClass;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EClass getDatamodelContainer()
	{
		return datamodelContainerEClass;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public EReference getDatamodelContainer_Datamodelattacker()
	{
		return (EReference)datamodelContainerEClass.getEStructuralFeatures().get(0);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public KAMP4attackModificationmarksFactory getKAMP4attackModificationmarksFactory()
	{
		return (KAMP4attackModificationmarksFactory)getEFactoryInstance();
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private boolean isCreated = false;

	/**
	 * Creates the meta-model objects for the package.  This method is
	 * guarded to have no affect on any invocation but its first.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public void createPackageContents()
	{
		if (isCreated) return;
		isCreated = true;

		// Create classes and their features
		abstractKAMP4attackModificationRepositoryEClass = createEClass(ABSTRACT_KAMP_4ATTACK_MODIFICATION_REPOSITORY);

		kamp4attackModificationRepositoryEClass = createEClass(KAMP_4ATTACK_MODIFICATION_REPOSITORY);

		kamp4attackSeedModificationsEClass = createEClass(KAMP_4ATTACK_SEED_MODIFICATIONS);
		createEReference(kamp4attackSeedModificationsEClass, KAMP_4ATTACK_SEED_MODIFICATIONS__ATTACKCOMPONENT);

		modifyEntityEClass = createEClass(MODIFY_ENTITY);

		attackerSelectionEClass = createEClass(ATTACKER_SELECTION);

		credentialChangeEClass = createEClass(CREDENTIAL_CHANGE);
		createEReference(credentialChangeEClass, CREDENTIAL_CHANGE__COMPROMISEDRESOURCE);
		createEReference(credentialChangeEClass, CREDENTIAL_CHANGE__COMPROMISEDASSEMBLY);
		createEReference(credentialChangeEClass, CREDENTIAL_CHANGE__CONTEXTCHANGE);
		createEAttribute(credentialChangeEClass, CREDENTIAL_CHANGE__CHANGED);
		createEReference(credentialChangeEClass, CREDENTIAL_CHANGE__COMPROMISEDLINKINGRESOURCE);
		createEReference(credentialChangeEClass, CREDENTIAL_CHANGE__COMPROMISEDSERVICE);
		createEReference(credentialChangeEClass, CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER);
		createEReference(credentialChangeEClass, CREDENTIAL_CHANGE__COMPROMISEDDATA);
		createEReference(credentialChangeEClass, CREDENTIAL_CHANGE__DATAMODELCONTAINER);

		compromisedResourceEClass = createEClass(COMPROMISED_RESOURCE);

		compromisedAssemblyEClass = createEClass(COMPROMISED_ASSEMBLY);

		contextChangeEClass = createEClass(CONTEXT_CHANGE);

		compromisedLinkingResourceEClass = createEClass(COMPROMISED_LINKING_RESOURCE);

		compromisedServiceEClass = createEClass(COMPROMISED_SERVICE);

		serviceRestrictionContainerEClass = createEClass(SERVICE_RESTRICTION_CONTAINER);
		createEReference(serviceRestrictionContainerEClass, SERVICE_RESTRICTION_CONTAINER__SERVICERESTRICTION);

		compromisedDataEClass = createEClass(COMPROMISED_DATA);

		datamodelContainerEClass = createEClass(DATAMODEL_CONTAINER);
		createEReference(datamodelContainerEClass, DATAMODEL_CONTAINER__DATAMODELATTACKER);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	private boolean isInitialized = false;

	/**
	 * Complete the initialization of the package and its meta-model.  This
	 * method is guarded to have no affect on any invocation but its first.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public void initializePackageContents()
	{
		if (isInitialized) return;
		isInitialized = true;

		// Initialize package
		setName(eNAME);
		setNsPrefix(eNS_PREFIX);
		setNsURI(eNS_URI);

		// Obtain other dependent packages
		ModificationmarksPackage theModificationmarksPackage = (ModificationmarksPackage)EPackage.Registry.INSTANCE.getEPackage(ModificationmarksPackage.eNS_URI);
		EntityPackage theEntityPackage = (EntityPackage)EPackage.Registry.INSTANCE.getEPackage(EntityPackage.eNS_URI);
		AttackerPackage theAttackerPackage = (AttackerPackage)EPackage.Registry.INSTANCE.getEPackage(AttackerPackage.eNS_URI);
		EcorePackage theEcorePackage = (EcorePackage)EPackage.Registry.INSTANCE.getEPackage(EcorePackage.eNS_URI);
		ResourceenvironmentPackage theResourceenvironmentPackage = (ResourceenvironmentPackage)EPackage.Registry.INSTANCE.getEPackage(ResourceenvironmentPackage.eNS_URI);
		CompositionPackage theCompositionPackage = (CompositionPackage)EPackage.Registry.INSTANCE.getEPackage(CompositionPackage.eNS_URI);
		SystemPackage theSystemPackage = (SystemPackage)EPackage.Registry.INSTANCE.getEPackage(SystemPackage.eNS_URI);
		StructurePackage theStructurePackage = (StructurePackage)EPackage.Registry.INSTANCE.getEPackage(StructurePackage.eNS_URI);

		// Create type parameters
		ETypeParameter abstractKAMP4attackModificationRepositoryEClass_T = addETypeParameter(abstractKAMP4attackModificationRepositoryEClass, "T");
		ETypeParameter modifyEntityEClass_T = addETypeParameter(modifyEntityEClass, "T");

		// Set bounds for type parameters
		EGenericType g1 = createEGenericType(this.getKAMP4attackSeedModifications());
		abstractKAMP4attackModificationRepositoryEClass_T.getEBounds().add(g1);
		g1 = createEGenericType(theEntityPackage.getEntity());
		modifyEntityEClass_T.getEBounds().add(g1);

		// Add supertypes to classes
		g1 = createEGenericType(theModificationmarksPackage.getAbstractModificationRepository());
		EGenericType g2 = createEGenericType(abstractKAMP4attackModificationRepositoryEClass_T);
		g1.getETypeArguments().add(g2);
		g2 = createEGenericType(theModificationmarksPackage.getChangePropagationStep());
		g1.getETypeArguments().add(g2);
		abstractKAMP4attackModificationRepositoryEClass.getEGenericSuperTypes().add(g1);
		g1 = createEGenericType(this.getAbstractKAMP4attackModificationRepository());
		g2 = createEGenericType(this.getKAMP4attackSeedModifications());
		g1.getETypeArguments().add(g2);
		kamp4attackModificationRepositoryEClass.getEGenericSuperTypes().add(g1);
		kamp4attackSeedModificationsEClass.getESuperTypes().add(theModificationmarksPackage.getAbstractSeedModifications());
		g1 = createEGenericType(theModificationmarksPackage.getAbstractModification());
		g2 = createEGenericType(modifyEntityEClass_T);
		g1.getETypeArguments().add(g2);
		g2 = createEGenericType(ecorePackage.getEObject());
		g1.getETypeArguments().add(g2);
		modifyEntityEClass.getEGenericSuperTypes().add(g1);
		g1 = createEGenericType(this.getModifyEntity());
		g2 = createEGenericType(theAttackerPackage.getAttacker());
		g1.getETypeArguments().add(g2);
		attackerSelectionEClass.getEGenericSuperTypes().add(g1);
		credentialChangeEClass.getESuperTypes().add(theModificationmarksPackage.getChangePropagationStep());
		g1 = createEGenericType(this.getModifyEntity());
		g2 = createEGenericType(theResourceenvironmentPackage.getResourceContainer());
		g1.getETypeArguments().add(g2);
		compromisedResourceEClass.getEGenericSuperTypes().add(g1);
		g1 = createEGenericType(this.getModifyEntity());
		g2 = createEGenericType(theCompositionPackage.getAssemblyContext());
		g1.getETypeArguments().add(g2);
		compromisedAssemblyEClass.getEGenericSuperTypes().add(g1);
		g1 = createEGenericType(this.getModifyEntity());
		g2 = createEGenericType(theSystemPackage.getUsageSpecification());
		g1.getETypeArguments().add(g2);
		contextChangeEClass.getEGenericSuperTypes().add(g1);
		g1 = createEGenericType(this.getModifyEntity());
		g2 = createEGenericType(theResourceenvironmentPackage.getLinkingResource());
		g1.getETypeArguments().add(g2);
		compromisedLinkingResourceEClass.getEGenericSuperTypes().add(g1);
		g1 = createEGenericType(this.getModifyEntity());
		g2 = createEGenericType(theStructurePackage.getServiceRestriction());
		g1.getETypeArguments().add(g2);
		compromisedServiceEClass.getEGenericSuperTypes().add(g1);
		g1 = createEGenericType(this.getModifyEntity());
		g2 = createEGenericType(theAttackerPackage.getDatamodelAttacker());
		g1.getETypeArguments().add(g2);
		compromisedDataEClass.getEGenericSuperTypes().add(g1);

		// Initialize classes, features, and operations; add parameters
		initEClass(abstractKAMP4attackModificationRepositoryEClass, AbstractKAMP4attackModificationRepository.class, "AbstractKAMP4attackModificationRepository", IS_ABSTRACT, !IS_INTERFACE, IS_GENERATED_INSTANCE_CLASS);

		initEClass(kamp4attackModificationRepositoryEClass, KAMP4attackModificationRepository.class, "KAMP4attackModificationRepository", !IS_ABSTRACT, !IS_INTERFACE, IS_GENERATED_INSTANCE_CLASS);

		initEClass(kamp4attackSeedModificationsEClass, KAMP4attackSeedModifications.class, "KAMP4attackSeedModifications", !IS_ABSTRACT, !IS_INTERFACE, IS_GENERATED_INSTANCE_CLASS);
		initEReference(getKAMP4attackSeedModifications_Attackcomponent(), this.getAttackerSelection(), null, "attackcomponent", null, 0, -1, KAMP4attackSeedModifications.class, !IS_TRANSIENT, !IS_VOLATILE, IS_CHANGEABLE, IS_COMPOSITE, !IS_RESOLVE_PROXIES, !IS_UNSETTABLE, IS_UNIQUE, !IS_DERIVED, IS_ORDERED);

		initEClass(modifyEntityEClass, ModifyEntity.class, "ModifyEntity", IS_ABSTRACT, !IS_INTERFACE, IS_GENERATED_INSTANCE_CLASS);

		initEClass(attackerSelectionEClass, AttackerSelection.class, "AttackerSelection", !IS_ABSTRACT, !IS_INTERFACE, IS_GENERATED_INSTANCE_CLASS);

		initEClass(credentialChangeEClass, CredentialChange.class, "CredentialChange", !IS_ABSTRACT, !IS_INTERFACE, IS_GENERATED_INSTANCE_CLASS);
		initEReference(getCredentialChange_Compromisedresource(), this.getCompromisedResource(), null, "compromisedresource", null, 0, -1, CredentialChange.class, !IS_TRANSIENT, !IS_VOLATILE, IS_CHANGEABLE, IS_COMPOSITE, !IS_RESOLVE_PROXIES, !IS_UNSETTABLE, IS_UNIQUE, !IS_DERIVED, IS_ORDERED);
		initEReference(getCredentialChange_Compromisedassembly(), this.getCompromisedAssembly(), null, "compromisedassembly", null, 0, -1, CredentialChange.class, !IS_TRANSIENT, !IS_VOLATILE, IS_CHANGEABLE, IS_COMPOSITE, !IS_RESOLVE_PROXIES, !IS_UNSETTABLE, IS_UNIQUE, !IS_DERIVED, IS_ORDERED);
		initEReference(getCredentialChange_Contextchange(), this.getContextChange(), null, "contextchange", null, 0, -1, CredentialChange.class, !IS_TRANSIENT, !IS_VOLATILE, IS_CHANGEABLE, IS_COMPOSITE, !IS_RESOLVE_PROXIES, !IS_UNSETTABLE, IS_UNIQUE, !IS_DERIVED, IS_ORDERED);
		initEAttribute(getCredentialChange_Changed(), theEcorePackage.getEBoolean(), "changed", null, 0, 1, CredentialChange.class, !IS_TRANSIENT, !IS_VOLATILE, IS_CHANGEABLE, !IS_UNSETTABLE, !IS_ID, IS_UNIQUE, !IS_DERIVED, IS_ORDERED);
		initEReference(getCredentialChange_Compromisedlinkingresource(), this.getCompromisedLinkingResource(), null, "compromisedlinkingresource", null, 0, -1, CredentialChange.class, !IS_TRANSIENT, !IS_VOLATILE, IS_CHANGEABLE, IS_COMPOSITE, !IS_RESOLVE_PROXIES, !IS_UNSETTABLE, IS_UNIQUE, !IS_DERIVED, IS_ORDERED);
		initEReference(getCredentialChange_Compromisedservice(), this.getCompromisedService(), null, "compromisedservice", null, 0, -1, CredentialChange.class, !IS_TRANSIENT, !IS_VOLATILE, IS_CHANGEABLE, IS_COMPOSITE, !IS_RESOLVE_PROXIES, !IS_UNSETTABLE, IS_UNIQUE, !IS_DERIVED, IS_ORDERED);
		initEReference(getCredentialChange_Servicerestrictioncontainer(), this.getServiceRestrictionContainer(), null, "servicerestrictioncontainer", null, 0, 1, CredentialChange.class, !IS_TRANSIENT, !IS_VOLATILE, IS_CHANGEABLE, IS_COMPOSITE, !IS_RESOLVE_PROXIES, !IS_UNSETTABLE, IS_UNIQUE, !IS_DERIVED, IS_ORDERED);
		initEReference(getCredentialChange_Compromiseddata(), this.getCompromisedData(), null, "compromiseddata", null, 0, -1, CredentialChange.class, !IS_TRANSIENT, !IS_VOLATILE, IS_CHANGEABLE, IS_COMPOSITE, !IS_RESOLVE_PROXIES, !IS_UNSETTABLE, IS_UNIQUE, !IS_DERIVED, IS_ORDERED);
		initEReference(getCredentialChange_Datamodelcontainer(), this.getDatamodelContainer(), null, "datamodelcontainer", null, 0, 1, CredentialChange.class, !IS_TRANSIENT, !IS_VOLATILE, IS_CHANGEABLE, IS_COMPOSITE, !IS_RESOLVE_PROXIES, !IS_UNSETTABLE, IS_UNIQUE, !IS_DERIVED, IS_ORDERED);

		initEClass(compromisedResourceEClass, CompromisedResource.class, "CompromisedResource", !IS_ABSTRACT, !IS_INTERFACE, IS_GENERATED_INSTANCE_CLASS);

		initEClass(compromisedAssemblyEClass, CompromisedAssembly.class, "CompromisedAssembly", !IS_ABSTRACT, !IS_INTERFACE, IS_GENERATED_INSTANCE_CLASS);

		initEClass(contextChangeEClass, ContextChange.class, "ContextChange", !IS_ABSTRACT, !IS_INTERFACE, IS_GENERATED_INSTANCE_CLASS);

		initEClass(compromisedLinkingResourceEClass, CompromisedLinkingResource.class, "CompromisedLinkingResource", !IS_ABSTRACT, !IS_INTERFACE, IS_GENERATED_INSTANCE_CLASS);

		initEClass(compromisedServiceEClass, CompromisedService.class, "CompromisedService", !IS_ABSTRACT, !IS_INTERFACE, IS_GENERATED_INSTANCE_CLASS);

		initEClass(serviceRestrictionContainerEClass, ServiceRestrictionContainer.class, "ServiceRestrictionContainer", !IS_ABSTRACT, !IS_INTERFACE, IS_GENERATED_INSTANCE_CLASS);
		initEReference(getServiceRestrictionContainer_Servicerestriction(), theStructurePackage.getServiceRestriction(), null, "servicerestriction", null, 0, -1, ServiceRestrictionContainer.class, !IS_TRANSIENT, !IS_VOLATILE, IS_CHANGEABLE, IS_COMPOSITE, !IS_RESOLVE_PROXIES, !IS_UNSETTABLE, IS_UNIQUE, !IS_DERIVED, IS_ORDERED);

		initEClass(compromisedDataEClass, CompromisedData.class, "CompromisedData", !IS_ABSTRACT, !IS_INTERFACE, IS_GENERATED_INSTANCE_CLASS);

		initEClass(datamodelContainerEClass, DatamodelContainer.class, "DatamodelContainer", !IS_ABSTRACT, !IS_INTERFACE, IS_GENERATED_INSTANCE_CLASS);
		initEReference(getDatamodelContainer_Datamodelattacker(), theAttackerPackage.getDatamodelAttacker(), null, "datamodelattacker", null, 0, -1, DatamodelContainer.class, !IS_TRANSIENT, !IS_VOLATILE, IS_CHANGEABLE, IS_COMPOSITE, !IS_RESOLVE_PROXIES, !IS_UNSETTABLE, IS_UNIQUE, !IS_DERIVED, IS_ORDERED);

		// Create resource
		createResource(eNS_URI);
	}

} //KAMP4attackModificationmarksPackageImpl
