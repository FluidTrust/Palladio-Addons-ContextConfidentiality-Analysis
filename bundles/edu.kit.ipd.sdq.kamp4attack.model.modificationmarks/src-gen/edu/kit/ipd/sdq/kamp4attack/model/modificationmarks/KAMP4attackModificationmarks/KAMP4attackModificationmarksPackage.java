/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks;

import edu.kit.ipd.sdq.kamp.model.modificationmarks.ModificationmarksPackage;

import org.eclipse.emf.ecore.EAttribute;
import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.EPackage;
import org.eclipse.emf.ecore.EReference;

/**
 * <!-- begin-user-doc -->
 * The <b>Package</b> for the model.
 * It contains accessors for the meta objects to represent
 * <ul>
 *   <li>each class,</li>
 *   <li>each feature of each class,</li>
 *   <li>each operation of each class,</li>
 *   <li>each enum,</li>
 *   <li>and each data type</li>
 * </ul>
 * <!-- end-user-doc -->
 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory
 * @model kind="package"
 * @generated
 */
public interface KAMP4attackModificationmarksPackage extends EPackage
{
	/**
	 * The package name.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	String eNAME = "KAMP4attackModificationmarks";

	/**
	 * The package namespace URI.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	String eNS_URI = "http://sdq.ipd.kit.edu/KAMP4attackModificationmarks/1.0";

	/**
	 * The package namespace name.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	String eNS_PREFIX = "KAMP4attackModificationmarks";

	/**
	 * The singleton instance of the package.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	KAMP4attackModificationmarksPackage eINSTANCE = edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl.init();

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.AbstractKAMP4attackModificationRepositoryImpl <em>Abstract KAMP 4attack Modification Repository</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.AbstractKAMP4attackModificationRepositoryImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getAbstractKAMP4attackModificationRepository()
	 * @generated
	 */
	int ABSTRACT_KAMP_4ATTACK_MODIFICATION_REPOSITORY = 0;

	/**
	 * The feature id for the '<em><b>Seed Modifications</b></em>' containment reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int ABSTRACT_KAMP_4ATTACK_MODIFICATION_REPOSITORY__SEED_MODIFICATIONS = ModificationmarksPackage.ABSTRACT_MODIFICATION_REPOSITORY__SEED_MODIFICATIONS;

	/**
	 * The feature id for the '<em><b>Change Propagation Steps</b></em>' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int ABSTRACT_KAMP_4ATTACK_MODIFICATION_REPOSITORY__CHANGE_PROPAGATION_STEPS = ModificationmarksPackage.ABSTRACT_MODIFICATION_REPOSITORY__CHANGE_PROPAGATION_STEPS;

	/**
	 * The number of structural features of the '<em>Abstract KAMP 4attack Modification Repository</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int ABSTRACT_KAMP_4ATTACK_MODIFICATION_REPOSITORY_FEATURE_COUNT = ModificationmarksPackage.ABSTRACT_MODIFICATION_REPOSITORY_FEATURE_COUNT + 0;

	/**
	 * The number of operations of the '<em>Abstract KAMP 4attack Modification Repository</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int ABSTRACT_KAMP_4ATTACK_MODIFICATION_REPOSITORY_OPERATION_COUNT = ModificationmarksPackage.ABSTRACT_MODIFICATION_REPOSITORY_OPERATION_COUNT + 0;

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationRepositoryImpl <em>KAMP 4attack Modification Repository</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationRepositoryImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getKAMP4attackModificationRepository()
	 * @generated
	 */
	int KAMP_4ATTACK_MODIFICATION_REPOSITORY = 1;

	/**
	 * The feature id for the '<em><b>Seed Modifications</b></em>' containment reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int KAMP_4ATTACK_MODIFICATION_REPOSITORY__SEED_MODIFICATIONS = ABSTRACT_KAMP_4ATTACK_MODIFICATION_REPOSITORY__SEED_MODIFICATIONS;

	/**
	 * The feature id for the '<em><b>Change Propagation Steps</b></em>' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int KAMP_4ATTACK_MODIFICATION_REPOSITORY__CHANGE_PROPAGATION_STEPS = ABSTRACT_KAMP_4ATTACK_MODIFICATION_REPOSITORY__CHANGE_PROPAGATION_STEPS;

	/**
	 * The number of structural features of the '<em>KAMP 4attack Modification Repository</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int KAMP_4ATTACK_MODIFICATION_REPOSITORY_FEATURE_COUNT = ABSTRACT_KAMP_4ATTACK_MODIFICATION_REPOSITORY_FEATURE_COUNT + 0;

	/**
	 * The number of operations of the '<em>KAMP 4attack Modification Repository</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int KAMP_4ATTACK_MODIFICATION_REPOSITORY_OPERATION_COUNT = ABSTRACT_KAMP_4ATTACK_MODIFICATION_REPOSITORY_OPERATION_COUNT + 0;

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackSeedModificationsImpl <em>KAMP 4attack Seed Modifications</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackSeedModificationsImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getKAMP4attackSeedModifications()
	 * @generated
	 */
	int KAMP_4ATTACK_SEED_MODIFICATIONS = 2;

	/**
	 * The feature id for the '<em><b>Attackcomponent</b></em>' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int KAMP_4ATTACK_SEED_MODIFICATIONS__ATTACKCOMPONENT = ModificationmarksPackage.ABSTRACT_SEED_MODIFICATIONS_FEATURE_COUNT + 0;

	/**
	 * The number of structural features of the '<em>KAMP 4attack Seed Modifications</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int KAMP_4ATTACK_SEED_MODIFICATIONS_FEATURE_COUNT = ModificationmarksPackage.ABSTRACT_SEED_MODIFICATIONS_FEATURE_COUNT + 1;

	/**
	 * The number of operations of the '<em>KAMP 4attack Seed Modifications</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int KAMP_4ATTACK_SEED_MODIFICATIONS_OPERATION_COUNT = ModificationmarksPackage.ABSTRACT_SEED_MODIFICATIONS_OPERATION_COUNT + 0;

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ModifyEntityImpl <em>Modify Entity</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ModifyEntityImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getModifyEntity()
	 * @generated
	 */
	int MODIFY_ENTITY = 3;

	/**
	 * The feature id for the '<em><b>Affected Element</b></em>' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int MODIFY_ENTITY__AFFECTED_ELEMENT = ModificationmarksPackage.ABSTRACT_MODIFICATION__AFFECTED_ELEMENT;

	/**
	 * The feature id for the '<em><b>Causing Elements</b></em>' reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int MODIFY_ENTITY__CAUSING_ELEMENTS = ModificationmarksPackage.ABSTRACT_MODIFICATION__CAUSING_ELEMENTS;

	/**
	 * The feature id for the '<em><b>Id</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int MODIFY_ENTITY__ID = ModificationmarksPackage.ABSTRACT_MODIFICATION__ID;

	/**
	 * The feature id for the '<em><b>Toolderived</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int MODIFY_ENTITY__TOOLDERIVED = ModificationmarksPackage.ABSTRACT_MODIFICATION__TOOLDERIVED;

	/**
	 * The feature id for the '<em><b>User Decision</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int MODIFY_ENTITY__USER_DECISION = ModificationmarksPackage.ABSTRACT_MODIFICATION__USER_DECISION;

	/**
	 * The number of structural features of the '<em>Modify Entity</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int MODIFY_ENTITY_FEATURE_COUNT = ModificationmarksPackage.ABSTRACT_MODIFICATION_FEATURE_COUNT + 0;

	/**
	 * The number of operations of the '<em>Modify Entity</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int MODIFY_ENTITY_OPERATION_COUNT = ModificationmarksPackage.ABSTRACT_MODIFICATION_OPERATION_COUNT + 0;

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.AttackerSelectionImpl <em>Attacker Selection</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.AttackerSelectionImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getAttackerSelection()
	 * @generated
	 */
	int ATTACKER_SELECTION = 4;

	/**
	 * The feature id for the '<em><b>Affected Element</b></em>' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int ATTACKER_SELECTION__AFFECTED_ELEMENT = MODIFY_ENTITY__AFFECTED_ELEMENT;

	/**
	 * The feature id for the '<em><b>Causing Elements</b></em>' reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int ATTACKER_SELECTION__CAUSING_ELEMENTS = MODIFY_ENTITY__CAUSING_ELEMENTS;

	/**
	 * The feature id for the '<em><b>Id</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int ATTACKER_SELECTION__ID = MODIFY_ENTITY__ID;

	/**
	 * The feature id for the '<em><b>Toolderived</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int ATTACKER_SELECTION__TOOLDERIVED = MODIFY_ENTITY__TOOLDERIVED;

	/**
	 * The feature id for the '<em><b>User Decision</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int ATTACKER_SELECTION__USER_DECISION = MODIFY_ENTITY__USER_DECISION;

	/**
	 * The number of structural features of the '<em>Attacker Selection</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int ATTACKER_SELECTION_FEATURE_COUNT = MODIFY_ENTITY_FEATURE_COUNT + 0;

	/**
	 * The number of operations of the '<em>Attacker Selection</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int ATTACKER_SELECTION_OPERATION_COUNT = MODIFY_ENTITY_OPERATION_COUNT + 0;

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CredentialChangeImpl <em>Credential Change</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CredentialChangeImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getCredentialChange()
	 * @generated
	 */
	int CREDENTIAL_CHANGE = 5;

	/**
	 * The feature id for the '<em><b>Compromisedresource</b></em>' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CREDENTIAL_CHANGE__COMPROMISEDRESOURCE = ModificationmarksPackage.CHANGE_PROPAGATION_STEP_FEATURE_COUNT + 0;

	/**
	 * The feature id for the '<em><b>Contextchange</b></em>' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CREDENTIAL_CHANGE__CONTEXTCHANGE = ModificationmarksPackage.CHANGE_PROPAGATION_STEP_FEATURE_COUNT + 1;

	/**
	 * The feature id for the '<em><b>Changed</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CREDENTIAL_CHANGE__CHANGED = ModificationmarksPackage.CHANGE_PROPAGATION_STEP_FEATURE_COUNT + 2;

	/**
	 * The feature id for the '<em><b>Compromisedlinkingresource</b></em>' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CREDENTIAL_CHANGE__COMPROMISEDLINKINGRESOURCE = ModificationmarksPackage.CHANGE_PROPAGATION_STEP_FEATURE_COUNT + 3;

	/**
	 * The feature id for the '<em><b>Compromisedservice</b></em>' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CREDENTIAL_CHANGE__COMPROMISEDSERVICE = ModificationmarksPackage.CHANGE_PROPAGATION_STEP_FEATURE_COUNT + 4;

	/**
	 * The feature id for the '<em><b>Servicerestrictioncontainer</b></em>' containment reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER = ModificationmarksPackage.CHANGE_PROPAGATION_STEP_FEATURE_COUNT + 5;

	/**
	 * The feature id for the '<em><b>Compromiseddata</b></em>' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CREDENTIAL_CHANGE__COMPROMISEDDATA = ModificationmarksPackage.CHANGE_PROPAGATION_STEP_FEATURE_COUNT + 6;

	/**
	 * The feature id for the '<em><b>Datamodelcontainer</b></em>' containment reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CREDENTIAL_CHANGE__DATAMODELCONTAINER = ModificationmarksPackage.CHANGE_PROPAGATION_STEP_FEATURE_COUNT + 7;

	/**
	 * The feature id for the '<em><b>Compromisedassembly</b></em>' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CREDENTIAL_CHANGE__COMPROMISEDASSEMBLY = ModificationmarksPackage.CHANGE_PROPAGATION_STEP_FEATURE_COUNT + 8;

	/**
	 * The feature id for the '<em><b>Assemblycontextdetailcontainer</b></em>' containment reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CREDENTIAL_CHANGE__ASSEMBLYCONTEXTDETAILCONTAINER = ModificationmarksPackage.CHANGE_PROPAGATION_STEP_FEATURE_COUNT + 9;

	/**
	 * The number of structural features of the '<em>Credential Change</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CREDENTIAL_CHANGE_FEATURE_COUNT = ModificationmarksPackage.CHANGE_PROPAGATION_STEP_FEATURE_COUNT + 10;

	/**
	 * The number of operations of the '<em>Credential Change</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CREDENTIAL_CHANGE_OPERATION_COUNT = ModificationmarksPackage.CHANGE_PROPAGATION_STEP_OPERATION_COUNT + 0;

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedResourceImpl <em>Compromised Resource</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedResourceImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getCompromisedResource()
	 * @generated
	 */
	int COMPROMISED_RESOURCE = 6;

	/**
	 * The feature id for the '<em><b>Affected Element</b></em>' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_RESOURCE__AFFECTED_ELEMENT = MODIFY_ENTITY__AFFECTED_ELEMENT;

	/**
	 * The feature id for the '<em><b>Causing Elements</b></em>' reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_RESOURCE__CAUSING_ELEMENTS = MODIFY_ENTITY__CAUSING_ELEMENTS;

	/**
	 * The feature id for the '<em><b>Id</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_RESOURCE__ID = MODIFY_ENTITY__ID;

	/**
	 * The feature id for the '<em><b>Toolderived</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_RESOURCE__TOOLDERIVED = MODIFY_ENTITY__TOOLDERIVED;

	/**
	 * The feature id for the '<em><b>User Decision</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_RESOURCE__USER_DECISION = MODIFY_ENTITY__USER_DECISION;

	/**
	 * The number of structural features of the '<em>Compromised Resource</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_RESOURCE_FEATURE_COUNT = MODIFY_ENTITY_FEATURE_COUNT + 0;

	/**
	 * The number of operations of the '<em>Compromised Resource</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_RESOURCE_OPERATION_COUNT = MODIFY_ENTITY_OPERATION_COUNT + 0;

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedAssemblyImpl <em>Compromised Assembly</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedAssemblyImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getCompromisedAssembly()
	 * @generated
	 */
	int COMPROMISED_ASSEMBLY = 7;

	/**
	 * The feature id for the '<em><b>Affected Element</b></em>' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_ASSEMBLY__AFFECTED_ELEMENT = MODIFY_ENTITY__AFFECTED_ELEMENT;

	/**
	 * The feature id for the '<em><b>Causing Elements</b></em>' reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_ASSEMBLY__CAUSING_ELEMENTS = MODIFY_ENTITY__CAUSING_ELEMENTS;

	/**
	 * The feature id for the '<em><b>Id</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_ASSEMBLY__ID = MODIFY_ENTITY__ID;

	/**
	 * The feature id for the '<em><b>Toolderived</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_ASSEMBLY__TOOLDERIVED = MODIFY_ENTITY__TOOLDERIVED;

	/**
	 * The feature id for the '<em><b>User Decision</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_ASSEMBLY__USER_DECISION = MODIFY_ENTITY__USER_DECISION;

	/**
	 * The number of structural features of the '<em>Compromised Assembly</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_ASSEMBLY_FEATURE_COUNT = MODIFY_ENTITY_FEATURE_COUNT + 0;

	/**
	 * The number of operations of the '<em>Compromised Assembly</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_ASSEMBLY_OPERATION_COUNT = MODIFY_ENTITY_OPERATION_COUNT + 0;

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ContextChangeImpl <em>Context Change</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ContextChangeImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getContextChange()
	 * @generated
	 */
	int CONTEXT_CHANGE = 8;

	/**
	 * The feature id for the '<em><b>Affected Element</b></em>' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CONTEXT_CHANGE__AFFECTED_ELEMENT = MODIFY_ENTITY__AFFECTED_ELEMENT;

	/**
	 * The feature id for the '<em><b>Causing Elements</b></em>' reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CONTEXT_CHANGE__CAUSING_ELEMENTS = MODIFY_ENTITY__CAUSING_ELEMENTS;

	/**
	 * The feature id for the '<em><b>Id</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CONTEXT_CHANGE__ID = MODIFY_ENTITY__ID;

	/**
	 * The feature id for the '<em><b>Toolderived</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CONTEXT_CHANGE__TOOLDERIVED = MODIFY_ENTITY__TOOLDERIVED;

	/**
	 * The feature id for the '<em><b>User Decision</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CONTEXT_CHANGE__USER_DECISION = MODIFY_ENTITY__USER_DECISION;

	/**
	 * The number of structural features of the '<em>Context Change</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CONTEXT_CHANGE_FEATURE_COUNT = MODIFY_ENTITY_FEATURE_COUNT + 0;

	/**
	 * The number of operations of the '<em>Context Change</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int CONTEXT_CHANGE_OPERATION_COUNT = MODIFY_ENTITY_OPERATION_COUNT + 0;

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedLinkingResourceImpl <em>Compromised Linking Resource</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedLinkingResourceImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getCompromisedLinkingResource()
	 * @generated
	 */
	int COMPROMISED_LINKING_RESOURCE = 9;

	/**
	 * The feature id for the '<em><b>Affected Element</b></em>' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_LINKING_RESOURCE__AFFECTED_ELEMENT = MODIFY_ENTITY__AFFECTED_ELEMENT;

	/**
	 * The feature id for the '<em><b>Causing Elements</b></em>' reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_LINKING_RESOURCE__CAUSING_ELEMENTS = MODIFY_ENTITY__CAUSING_ELEMENTS;

	/**
	 * The feature id for the '<em><b>Id</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_LINKING_RESOURCE__ID = MODIFY_ENTITY__ID;

	/**
	 * The feature id for the '<em><b>Toolderived</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_LINKING_RESOURCE__TOOLDERIVED = MODIFY_ENTITY__TOOLDERIVED;

	/**
	 * The feature id for the '<em><b>User Decision</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_LINKING_RESOURCE__USER_DECISION = MODIFY_ENTITY__USER_DECISION;

	/**
	 * The number of structural features of the '<em>Compromised Linking Resource</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_LINKING_RESOURCE_FEATURE_COUNT = MODIFY_ENTITY_FEATURE_COUNT + 0;

	/**
	 * The number of operations of the '<em>Compromised Linking Resource</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_LINKING_RESOURCE_OPERATION_COUNT = MODIFY_ENTITY_OPERATION_COUNT + 0;

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedServiceImpl <em>Compromised Service</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedServiceImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getCompromisedService()
	 * @generated
	 */
	int COMPROMISED_SERVICE = 10;

	/**
	 * The feature id for the '<em><b>Affected Element</b></em>' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_SERVICE__AFFECTED_ELEMENT = MODIFY_ENTITY__AFFECTED_ELEMENT;

	/**
	 * The feature id for the '<em><b>Causing Elements</b></em>' reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_SERVICE__CAUSING_ELEMENTS = MODIFY_ENTITY__CAUSING_ELEMENTS;

	/**
	 * The feature id for the '<em><b>Id</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_SERVICE__ID = MODIFY_ENTITY__ID;

	/**
	 * The feature id for the '<em><b>Toolderived</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_SERVICE__TOOLDERIVED = MODIFY_ENTITY__TOOLDERIVED;

	/**
	 * The feature id for the '<em><b>User Decision</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_SERVICE__USER_DECISION = MODIFY_ENTITY__USER_DECISION;

	/**
	 * The number of structural features of the '<em>Compromised Service</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_SERVICE_FEATURE_COUNT = MODIFY_ENTITY_FEATURE_COUNT + 0;

	/**
	 * The number of operations of the '<em>Compromised Service</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_SERVICE_OPERATION_COUNT = MODIFY_ENTITY_OPERATION_COUNT + 0;

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ServiceRestrictionContainerImpl <em>Service Restriction Container</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ServiceRestrictionContainerImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getServiceRestrictionContainer()
	 * @generated
	 */
	int SERVICE_RESTRICTION_CONTAINER = 11;

	/**
	 * The feature id for the '<em><b>Servicerestriction</b></em>' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int SERVICE_RESTRICTION_CONTAINER__SERVICERESTRICTION = 0;

	/**
	 * The number of structural features of the '<em>Service Restriction Container</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int SERVICE_RESTRICTION_CONTAINER_FEATURE_COUNT = 1;

	/**
	 * The number of operations of the '<em>Service Restriction Container</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int SERVICE_RESTRICTION_CONTAINER_OPERATION_COUNT = 0;

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedDataImpl <em>Compromised Data</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedDataImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getCompromisedData()
	 * @generated
	 */
	int COMPROMISED_DATA = 12;

	/**
	 * The feature id for the '<em><b>Affected Element</b></em>' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_DATA__AFFECTED_ELEMENT = MODIFY_ENTITY__AFFECTED_ELEMENT;

	/**
	 * The feature id for the '<em><b>Causing Elements</b></em>' reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_DATA__CAUSING_ELEMENTS = MODIFY_ENTITY__CAUSING_ELEMENTS;

	/**
	 * The feature id for the '<em><b>Id</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_DATA__ID = MODIFY_ENTITY__ID;

	/**
	 * The feature id for the '<em><b>Toolderived</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_DATA__TOOLDERIVED = MODIFY_ENTITY__TOOLDERIVED;

	/**
	 * The feature id for the '<em><b>User Decision</b></em>' attribute.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_DATA__USER_DECISION = MODIFY_ENTITY__USER_DECISION;

	/**
	 * The number of structural features of the '<em>Compromised Data</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_DATA_FEATURE_COUNT = MODIFY_ENTITY_FEATURE_COUNT + 0;

	/**
	 * The number of operations of the '<em>Compromised Data</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int COMPROMISED_DATA_OPERATION_COUNT = MODIFY_ENTITY_OPERATION_COUNT + 0;

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.DatamodelContainerImpl <em>Datamodel Container</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.DatamodelContainerImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getDatamodelContainer()
	 * @generated
	 */
	int DATAMODEL_CONTAINER = 13;

	/**
	 * The feature id for the '<em><b>Datamodelattacker</b></em>' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int DATAMODEL_CONTAINER__DATAMODELATTACKER = 0;

	/**
	 * The number of structural features of the '<em>Datamodel Container</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int DATAMODEL_CONTAINER_FEATURE_COUNT = 1;

	/**
	 * The number of operations of the '<em>Datamodel Container</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int DATAMODEL_CONTAINER_OPERATION_COUNT = 0;

	/**
	 * The meta object id for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.AssemblyContextDetailContainerImpl <em>Assembly Context Detail Container</em>}' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.AssemblyContextDetailContainerImpl
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getAssemblyContextDetailContainer()
	 * @generated
	 */
	int ASSEMBLY_CONTEXT_DETAIL_CONTAINER = 14;

	/**
	 * The feature id for the '<em><b>Compromisedassembly</b></em>' containment reference list.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int ASSEMBLY_CONTEXT_DETAIL_CONTAINER__COMPROMISEDASSEMBLY = 0;

	/**
	 * The number of structural features of the '<em>Assembly Context Detail Container</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int ASSEMBLY_CONTEXT_DETAIL_CONTAINER_FEATURE_COUNT = 1;

	/**
	 * The number of operations of the '<em>Assembly Context Detail Container</em>' class.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 * @ordered
	 */
	int ASSEMBLY_CONTEXT_DETAIL_CONTAINER_OPERATION_COUNT = 0;


	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AbstractKAMP4attackModificationRepository <em>Abstract KAMP 4attack Modification Repository</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>Abstract KAMP 4attack Modification Repository</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AbstractKAMP4attackModificationRepository
	 * @generated
	 */
	EClass getAbstractKAMP4attackModificationRepository();

	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationRepository <em>KAMP 4attack Modification Repository</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>KAMP 4attack Modification Repository</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationRepository
	 * @generated
	 */
	EClass getKAMP4attackModificationRepository();

	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackSeedModifications <em>KAMP 4attack Seed Modifications</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>KAMP 4attack Seed Modifications</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackSeedModifications
	 * @generated
	 */
	EClass getKAMP4attackSeedModifications();

	/**
	 * Returns the meta object for the containment reference list '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackSeedModifications#getAttackcomponent <em>Attackcomponent</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for the containment reference list '<em>Attackcomponent</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackSeedModifications#getAttackcomponent()
	 * @see #getKAMP4attackSeedModifications()
	 * @generated
	 */
	EReference getKAMP4attackSeedModifications_Attackcomponent();

	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ModifyEntity <em>Modify Entity</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>Modify Entity</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ModifyEntity
	 * @generated
	 */
	EClass getModifyEntity();

	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AttackerSelection <em>Attacker Selection</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>Attacker Selection</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AttackerSelection
	 * @generated
	 */
	EClass getAttackerSelection();

	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange <em>Credential Change</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>Credential Change</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange
	 * @generated
	 */
	EClass getCredentialChange();

	/**
	 * Returns the meta object for the containment reference list '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getCompromisedresource <em>Compromisedresource</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for the containment reference list '<em>Compromisedresource</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getCompromisedresource()
	 * @see #getCredentialChange()
	 * @generated
	 */
	EReference getCredentialChange_Compromisedresource();

	/**
	 * Returns the meta object for the containment reference list '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getContextchange <em>Contextchange</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for the containment reference list '<em>Contextchange</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getContextchange()
	 * @see #getCredentialChange()
	 * @generated
	 */
	EReference getCredentialChange_Contextchange();

	/**
	 * Returns the meta object for the attribute '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#isChanged <em>Changed</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for the attribute '<em>Changed</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#isChanged()
	 * @see #getCredentialChange()
	 * @generated
	 */
	EAttribute getCredentialChange_Changed();

	/**
	 * Returns the meta object for the containment reference list '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getCompromisedlinkingresource <em>Compromisedlinkingresource</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for the containment reference list '<em>Compromisedlinkingresource</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getCompromisedlinkingresource()
	 * @see #getCredentialChange()
	 * @generated
	 */
	EReference getCredentialChange_Compromisedlinkingresource();

	/**
	 * Returns the meta object for the containment reference list '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getCompromisedservice <em>Compromisedservice</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for the containment reference list '<em>Compromisedservice</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getCompromisedservice()
	 * @see #getCredentialChange()
	 * @generated
	 */
	EReference getCredentialChange_Compromisedservice();

	/**
	 * Returns the meta object for the containment reference '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getServicerestrictioncontainer <em>Servicerestrictioncontainer</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for the containment reference '<em>Servicerestrictioncontainer</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getServicerestrictioncontainer()
	 * @see #getCredentialChange()
	 * @generated
	 */
	EReference getCredentialChange_Servicerestrictioncontainer();

	/**
	 * Returns the meta object for the containment reference list '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getCompromiseddata <em>Compromiseddata</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for the containment reference list '<em>Compromiseddata</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getCompromiseddata()
	 * @see #getCredentialChange()
	 * @generated
	 */
	EReference getCredentialChange_Compromiseddata();

	/**
	 * Returns the meta object for the containment reference '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getDatamodelcontainer <em>Datamodelcontainer</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for the containment reference '<em>Datamodelcontainer</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getDatamodelcontainer()
	 * @see #getCredentialChange()
	 * @generated
	 */
	EReference getCredentialChange_Datamodelcontainer();

	/**
	 * Returns the meta object for the containment reference list '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getCompromisedassembly <em>Compromisedassembly</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for the containment reference list '<em>Compromisedassembly</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getCompromisedassembly()
	 * @see #getCredentialChange()
	 * @generated
	 */
	EReference getCredentialChange_Compromisedassembly();

	/**
	 * Returns the meta object for the containment reference '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getAssemblycontextdetailcontainer <em>Assemblycontextdetailcontainer</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for the containment reference '<em>Assemblycontextdetailcontainer</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange#getAssemblycontextdetailcontainer()
	 * @see #getCredentialChange()
	 * @generated
	 */
	EReference getCredentialChange_Assemblycontextdetailcontainer();

	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource <em>Compromised Resource</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>Compromised Resource</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource
	 * @generated
	 */
	EClass getCompromisedResource();

	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly <em>Compromised Assembly</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>Compromised Assembly</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly
	 * @generated
	 */
	EClass getCompromisedAssembly();

	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange <em>Context Change</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>Context Change</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange
	 * @generated
	 */
	EClass getContextChange();

	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource <em>Compromised Linking Resource</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>Compromised Linking Resource</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource
	 * @generated
	 */
	EClass getCompromisedLinkingResource();

	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedService <em>Compromised Service</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>Compromised Service</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedService
	 * @generated
	 */
	EClass getCompromisedService();

	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ServiceRestrictionContainer <em>Service Restriction Container</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>Service Restriction Container</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ServiceRestrictionContainer
	 * @generated
	 */
	EClass getServiceRestrictionContainer();

	/**
	 * Returns the meta object for the containment reference list '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ServiceRestrictionContainer#getServicerestriction <em>Servicerestriction</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for the containment reference list '<em>Servicerestriction</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ServiceRestrictionContainer#getServicerestriction()
	 * @see #getServiceRestrictionContainer()
	 * @generated
	 */
	EReference getServiceRestrictionContainer_Servicerestriction();

	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedData <em>Compromised Data</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>Compromised Data</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedData
	 * @generated
	 */
	EClass getCompromisedData();

	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.DatamodelContainer <em>Datamodel Container</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>Datamodel Container</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.DatamodelContainer
	 * @generated
	 */
	EClass getDatamodelContainer();

	/**
	 * Returns the meta object for the containment reference list '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.DatamodelContainer#getDatamodelattacker <em>Datamodelattacker</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for the containment reference list '<em>Datamodelattacker</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.DatamodelContainer#getDatamodelattacker()
	 * @see #getDatamodelContainer()
	 * @generated
	 */
	EReference getDatamodelContainer_Datamodelattacker();

	/**
	 * Returns the meta object for class '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AssemblyContextDetailContainer <em>Assembly Context Detail Container</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for class '<em>Assembly Context Detail Container</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AssemblyContextDetailContainer
	 * @generated
	 */
	EClass getAssemblyContextDetailContainer();

	/**
	 * Returns the meta object for the containment reference list '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AssemblyContextDetailContainer#getCompromisedassembly <em>Compromisedassembly</em>}'.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the meta object for the containment reference list '<em>Compromisedassembly</em>'.
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.AssemblyContextDetailContainer#getCompromisedassembly()
	 * @see #getAssemblyContextDetailContainer()
	 * @generated
	 */
	EReference getAssemblyContextDetailContainer_Compromisedassembly();

	/**
	 * Returns the factory that creates the instances of the model.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the factory that creates the instances of the model.
	 * @generated
	 */
	KAMP4attackModificationmarksFactory getKAMP4attackModificationmarksFactory();

	/**
	 * <!-- begin-user-doc -->
	 * Defines literals for the meta objects that represent
	 * <ul>
	 *   <li>each class,</li>
	 *   <li>each feature of each class,</li>
	 *   <li>each operation of each class,</li>
	 *   <li>each enum,</li>
	 *   <li>and each data type</li>
	 * </ul>
	 * <!-- end-user-doc -->
	 * @generated
	 */
	interface Literals
	{
		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.AbstractKAMP4attackModificationRepositoryImpl <em>Abstract KAMP 4attack Modification Repository</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.AbstractKAMP4attackModificationRepositoryImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getAbstractKAMP4attackModificationRepository()
		 * @generated
		 */
		EClass ABSTRACT_KAMP_4ATTACK_MODIFICATION_REPOSITORY = eINSTANCE.getAbstractKAMP4attackModificationRepository();

		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationRepositoryImpl <em>KAMP 4attack Modification Repository</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationRepositoryImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getKAMP4attackModificationRepository()
		 * @generated
		 */
		EClass KAMP_4ATTACK_MODIFICATION_REPOSITORY = eINSTANCE.getKAMP4attackModificationRepository();

		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackSeedModificationsImpl <em>KAMP 4attack Seed Modifications</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackSeedModificationsImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getKAMP4attackSeedModifications()
		 * @generated
		 */
		EClass KAMP_4ATTACK_SEED_MODIFICATIONS = eINSTANCE.getKAMP4attackSeedModifications();

		/**
		 * The meta object literal for the '<em><b>Attackcomponent</b></em>' containment reference list feature.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @generated
		 */
		EReference KAMP_4ATTACK_SEED_MODIFICATIONS__ATTACKCOMPONENT = eINSTANCE.getKAMP4attackSeedModifications_Attackcomponent();

		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ModifyEntityImpl <em>Modify Entity</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ModifyEntityImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getModifyEntity()
		 * @generated
		 */
		EClass MODIFY_ENTITY = eINSTANCE.getModifyEntity();

		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.AttackerSelectionImpl <em>Attacker Selection</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.AttackerSelectionImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getAttackerSelection()
		 * @generated
		 */
		EClass ATTACKER_SELECTION = eINSTANCE.getAttackerSelection();

		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CredentialChangeImpl <em>Credential Change</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CredentialChangeImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getCredentialChange()
		 * @generated
		 */
		EClass CREDENTIAL_CHANGE = eINSTANCE.getCredentialChange();

		/**
		 * The meta object literal for the '<em><b>Compromisedresource</b></em>' containment reference list feature.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @generated
		 */
		EReference CREDENTIAL_CHANGE__COMPROMISEDRESOURCE = eINSTANCE.getCredentialChange_Compromisedresource();

		/**
		 * The meta object literal for the '<em><b>Contextchange</b></em>' containment reference list feature.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @generated
		 */
		EReference CREDENTIAL_CHANGE__CONTEXTCHANGE = eINSTANCE.getCredentialChange_Contextchange();

		/**
		 * The meta object literal for the '<em><b>Changed</b></em>' attribute feature.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @generated
		 */
		EAttribute CREDENTIAL_CHANGE__CHANGED = eINSTANCE.getCredentialChange_Changed();

		/**
		 * The meta object literal for the '<em><b>Compromisedlinkingresource</b></em>' containment reference list feature.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @generated
		 */
		EReference CREDENTIAL_CHANGE__COMPROMISEDLINKINGRESOURCE = eINSTANCE.getCredentialChange_Compromisedlinkingresource();

		/**
		 * The meta object literal for the '<em><b>Compromisedservice</b></em>' containment reference list feature.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @generated
		 */
		EReference CREDENTIAL_CHANGE__COMPROMISEDSERVICE = eINSTANCE.getCredentialChange_Compromisedservice();

		/**
		 * The meta object literal for the '<em><b>Servicerestrictioncontainer</b></em>' containment reference feature.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @generated
		 */
		EReference CREDENTIAL_CHANGE__SERVICERESTRICTIONCONTAINER = eINSTANCE.getCredentialChange_Servicerestrictioncontainer();

		/**
		 * The meta object literal for the '<em><b>Compromiseddata</b></em>' containment reference list feature.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @generated
		 */
		EReference CREDENTIAL_CHANGE__COMPROMISEDDATA = eINSTANCE.getCredentialChange_Compromiseddata();

		/**
		 * The meta object literal for the '<em><b>Datamodelcontainer</b></em>' containment reference feature.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @generated
		 */
		EReference CREDENTIAL_CHANGE__DATAMODELCONTAINER = eINSTANCE.getCredentialChange_Datamodelcontainer();

		/**
		 * The meta object literal for the '<em><b>Compromisedassembly</b></em>' containment reference list feature.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @generated
		 */
		EReference CREDENTIAL_CHANGE__COMPROMISEDASSEMBLY = eINSTANCE.getCredentialChange_Compromisedassembly();

		/**
		 * The meta object literal for the '<em><b>Assemblycontextdetailcontainer</b></em>' containment reference feature.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @generated
		 */
		EReference CREDENTIAL_CHANGE__ASSEMBLYCONTEXTDETAILCONTAINER = eINSTANCE.getCredentialChange_Assemblycontextdetailcontainer();

		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedResourceImpl <em>Compromised Resource</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedResourceImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getCompromisedResource()
		 * @generated
		 */
		EClass COMPROMISED_RESOURCE = eINSTANCE.getCompromisedResource();

		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedAssemblyImpl <em>Compromised Assembly</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedAssemblyImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getCompromisedAssembly()
		 * @generated
		 */
		EClass COMPROMISED_ASSEMBLY = eINSTANCE.getCompromisedAssembly();

		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ContextChangeImpl <em>Context Change</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ContextChangeImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getContextChange()
		 * @generated
		 */
		EClass CONTEXT_CHANGE = eINSTANCE.getContextChange();

		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedLinkingResourceImpl <em>Compromised Linking Resource</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedLinkingResourceImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getCompromisedLinkingResource()
		 * @generated
		 */
		EClass COMPROMISED_LINKING_RESOURCE = eINSTANCE.getCompromisedLinkingResource();

		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedServiceImpl <em>Compromised Service</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedServiceImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getCompromisedService()
		 * @generated
		 */
		EClass COMPROMISED_SERVICE = eINSTANCE.getCompromisedService();

		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ServiceRestrictionContainerImpl <em>Service Restriction Container</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.ServiceRestrictionContainerImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getServiceRestrictionContainer()
		 * @generated
		 */
		EClass SERVICE_RESTRICTION_CONTAINER = eINSTANCE.getServiceRestrictionContainer();

		/**
		 * The meta object literal for the '<em><b>Servicerestriction</b></em>' containment reference list feature.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @generated
		 */
		EReference SERVICE_RESTRICTION_CONTAINER__SERVICERESTRICTION = eINSTANCE.getServiceRestrictionContainer_Servicerestriction();

		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedDataImpl <em>Compromised Data</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedDataImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getCompromisedData()
		 * @generated
		 */
		EClass COMPROMISED_DATA = eINSTANCE.getCompromisedData();

		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.DatamodelContainerImpl <em>Datamodel Container</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.DatamodelContainerImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getDatamodelContainer()
		 * @generated
		 */
		EClass DATAMODEL_CONTAINER = eINSTANCE.getDatamodelContainer();

		/**
		 * The meta object literal for the '<em><b>Datamodelattacker</b></em>' containment reference list feature.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @generated
		 */
		EReference DATAMODEL_CONTAINER__DATAMODELATTACKER = eINSTANCE.getDatamodelContainer_Datamodelattacker();

		/**
		 * The meta object literal for the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.AssemblyContextDetailContainerImpl <em>Assembly Context Detail Container</em>}' class.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.AssemblyContextDetailContainerImpl
		 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.KAMP4attackModificationmarksPackageImpl#getAssemblyContextDetailContainer()
		 * @generated
		 */
		EClass ASSEMBLY_CONTEXT_DETAIL_CONTAINER = eINSTANCE.getAssemblyContextDetailContainer();

		/**
		 * The meta object literal for the '<em><b>Compromisedassembly</b></em>' containment reference list feature.
		 * <!-- begin-user-doc -->
		 * <!-- end-user-doc -->
		 * @generated
		 */
		EReference ASSEMBLY_CONTEXT_DETAIL_CONTAINER__COMPROMISEDASSEMBLY = eINSTANCE.getAssemblyContextDetailContainer_Compromisedassembly();

	}

} //KAMP4attackModificationmarksPackage
