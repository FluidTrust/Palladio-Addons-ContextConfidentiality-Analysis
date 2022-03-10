package edu.kit.ipd.sdq.attacksurface.tests;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.resource.Resource;
import org.junit.jupiter.api.BeforeEach;
import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerSpecification;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.SurfaceAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackSpecificationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AvailabilityImpact;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CVEVulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.CWEBasedVulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.ContextFactory;
import org.palladiosimulator.pcm.confidentiality.context.analysis.testframework.BaseTest;
import org.palladiosimulator.pcm.confidentiality.context.system.SystemFactory;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.Attribute;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.AttributeValue;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.DataTypes;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.SimpleAttribute;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.SystemcontextFactory;
import org.palladiosimulator.pcm.confidentiality.context.xacml.generation.api.PCMBlackBoard;
import org.palladiosimulator.pcm.confidentiality.context.xacml.javapdp.XACMLGenerator;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.ResourceEnvironment;
import org.palladiosimulator.pcm.system.System;

import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
//TODO
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.CachePDP;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationRepository;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

public abstract class AbstractModelTest extends BaseTest {
    private static final String ROOT_STR = "root";

    protected String PATH_ATTACKER;
    protected String PATH_ASSEMBLY;
    protected String PATH_ALLOCATION;
    protected String PATH_CONTEXT;
    protected String PATH_MODIFICATION;
    protected String PATH_REPOSITORY;
    protected String PATH_USAGE;
    protected String PATH_RESOURCES;

    protected System assembly;
    protected ResourceEnvironment environment;
    protected Allocation allocation;
    protected ConfidentialAccessSpecification context;
    protected AttackerSpecification attacker;
    protected KAMP4attackModificationRepository modification;
    
    private AttackGraph attackGraph;
    private CredentialChange changes;

    private String pathXACML = "test.xml";

    final protected BlackboardWrapper getBlackboardWrapper() {

        return new BlackboardWrapper(this.modification, this.assembly, this.environment, this.allocation,
                this.context.getPcmspecificationcontainer(), this.attacker.getSystemintegration(), this.eval);
    }
    
    protected final AttackGraph getAttackGraph() {
        return this.attackGraph;
    }
    
    protected final void resetAttackGraphAndChanges() {
        this.attackGraph = new AttackGraph(getCriticalEntity());
        this.changes = KAMP4attackModificationmarksFactory.eINSTANCE.createCredentialChange();
    }

    protected Entity getCriticalEntity() {
        final var pcmElement = this.attacker.getAttackers().getSurfaceattacker().get(0).getCriticalElement();
        return PCMElementType.typeOf(pcmElement).getEntity(pcmElement);
    }
    
    protected Entity getFirstEntityByName(final String namePart) {
        final Set<Entity> allEntities = new HashSet<>(this.assembly.getAssemblyContexts__ComposedStructure());
        allEntities.addAll(this.environment.getResourceContainer_ResourceEnvironment());
        allEntities.addAll(this.environment.getLinkingResources__ResourceEnvironment());
        return allEntities
                .stream()
                .filter(e -> e.getEntityName().contains(namePart))
                .findFirst().orElse(null);
    }

    protected final CredentialChange getChanges() {
        return this.changes;
    }

    @Override
    protected List<String> getModelsPath() {
        final var list = new ArrayList<String>();

        list.add(this.PATH_ASSEMBLY);
        list.add(this.PATH_ALLOCATION);
        list.add(this.PATH_RESOURCES);
        list.add(this.PATH_USAGE);
        list.add(this.PATH_CONTEXT);
        list.add(this.PATH_ATTACKER);
        list.add(this.PATH_MODIFICATION);

        return list;
    }

    @Override
    protected void assignValues(final List<Resource> list) {
        this.assembly = this.getModel(list, System.class);
        this.environment = this.getModel(list, ResourceEnvironment.class);
        this.allocation = this.getModel(list, Allocation.class);
        this.context = this.getModel(list, ConfidentialAccessSpecification.class);
        this.attacker = this.getModel(list, AttackerSpecification.class);
        this.modification = this.getModel(list, KAMP4attackModificationRepository.class);
    }

    @Override
    protected void generateXML() {
        var generator = new XACMLGenerator();
        var blackboard = new PCMBlackBoard(this.assembly, null, this.environment);
        generator.generateXACML(blackboard, this.context, this.pathXACML);
    }

    protected UsageSpecification createContext(final String name) {
        final var contextAccess = SystemFactory.eINSTANCE.createUsageSpecification();

        final var attribute = SystemcontextFactory.eINSTANCE.createSimpleAttribute();
        var attributeValue = SystemcontextFactory.eINSTANCE.createAttributeValue();
        attributeValue.getValues().add(name);
        attributeValue.setType(DataTypes.STRING);
        attribute.getAttributevalue().add(attributeValue);

        contextAccess.setEntityName(name);
        contextAccess.setAttribute(attribute);
        contextAccess.setAttributevalue(attributeValue);
        this.context.getAttributes().getAttribute().add(attribute);
        this.context.getPcmspecificationcontainer().getUsagespecification().add(contextAccess);
        return contextAccess;
    }
    
    protected SurfaceAttacker getSurfaceAttacker() {
        assert attacker.getAttackers().getSurfaceattacker().size() == 1;
        return attacker.getAttackers().getSurfaceattacker().get(0); 
    }

    protected void createAvailabilityImpactFilter() {
        final var filterCriteria = this.getSurfaceAttacker().getFiltercriteria();
        final var impactFilter = AttackerFactory.eINSTANCE.createImpactVulnerabilityFilterCriterion();
        impactFilter.setAvailabilityImpactMinimum(AvailabilityImpact.HIGH);
        filterCriteria.add(impactFilter);
    }
    
    protected void createCredentialFilter() {
        final var filterCriteria = this.getSurfaceAttacker().getFiltercriteria();
        final var impactFilter = AttackerFactory.eINSTANCE.createInitialCredentialFilterCriterion();
        impactFilter.getProhibitedInitialCredentials().add(createRootCredentialsIfNecessary());
        filterCriteria.add(impactFilter);
    }

    protected ContextChange toChange(UsageSpecification credentials) {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        change.setAffectedElement(credentials);
        change.setToolderived(true);
        return change;
    }
    
    protected CredentialChange addRootAccess() {
        final var credentialList = getSurfaceAttacker().getAttacker().getCredentials();
        credentialList.add(getRootCredentials());
        //TODO adapt if changes are no longer used
        final var changes = getChanges();
        changes.getContextchange().add(toChange(getRootCredentials()));
        
        generateXML();
        return changes;
    }
    
    protected void removeRootAccess() {
        final var credentialList = getSurfaceAttacker().getAttacker().getCredentials();
        credentialList.remove(credentialList.size() - 1);
    }
    
    private UsageSpecification getRootCredentials() {
        return getFirstByName(ROOT_STR);
    }
    
    protected UsageSpecification createRootCredentialsIfNecessary() {
        if (getRootCredentials() == null) {
            final UsageSpecification root = SystemFactory.eINSTANCE.createUsageSpecification();
            root.setEntityName(ROOT_STR);
            root.setAttribute(createRootAttribute());
            root.setAttributevalue(root.getAttribute().getAttributevalue().get(0));
            this.context.getPcmspecificationcontainer()
                .getUsagespecification().add(root);
        }
        return getRootCredentials();
    }
    
    private Attribute createRootAttribute() {
        final SimpleAttribute attribute = SystemcontextFactory.eINSTANCE.createSimpleAttribute();
        attribute.setEntityName("Role");
        attribute.setEnvironment(false);
        final AttributeValue value = SystemcontextFactory.eINSTANCE.createAttributeValue();
        value.getValues().add(ROOT_STR);
        value.setType(DataTypes.STRING);
        attribute.getAttributevalue().add(value);
        this.context.getAttributes().getAttribute().add(attribute);
        return attribute;
    }

    protected UsageSpecification getFirstByName(final String namePart) {
        return this.context.getPcmspecificationcontainer().getUsagespecification()
                .stream()
                .filter(u -> u.getEntityName().contains(namePart))
                .findFirst().orElse(null);
    }
    
    @BeforeEach
    public void addAllPossibleAttacks() {
        var vulnerabilities = attacker.getVulnerabilites().getVulnerability();
        final var attacks = CollectionHelper.removeDuplicates(vulnerabilities)
            .stream()
            .map(this::toAttack)
            .flatMap(Set::stream)
            .filter(Objects::nonNull)
            .collect(Collectors.toSet());
        getSurfaceAttacker().getAttacker().getAttacks().addAll(attacks);
    }
    
    private Set<Attack> toAttack(final Vulnerability vulnerability) {
        if (vulnerability instanceof CVEVulnerability) {
            final Set<Attack> attacks = new HashSet<>();;
            final var cveVuln = (CVEVulnerability)vulnerability;
            final var attack = AttackSpecificationFactory.eINSTANCE.createCVEAttack();
            attack.setCategory(cveVuln.getCveID());
            attacks.add(attack);
            return attacks;
        } else if (vulnerability instanceof CWEBasedVulnerability) {
            final Set<Attack> attacks = new HashSet<>();;
            final var cweVuln = (CWEBasedVulnerability)vulnerability;
            for (final var id : cweVuln.getCweID()) {
                final var attack = AttackSpecificationFactory.eINSTANCE.createCWEAttack();
                attack.setCategory(id);
                attacks.add(attack);
            }
            return attacks;
        }
        return new HashSet<>(); //TODO or exception unknown vulnerability type
    }
    
    @BeforeEach
    public void generateXMLBeforeEachTest() {
        generateXML();
    }
    
    @BeforeEach
    public void clearCache() {
        resetAttackGraphAndChanges();
        CachePDP.instance().clearCache();
        CacheCompromised.instance().reset();
    }
}
