package edu.kit.ipd.sdq.attacksurface.tests;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.emf.ecore.resource.Resource;
import org.junit.jupiter.api.BeforeEach;
import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerSpecification;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.SurfaceAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AvailabilityImpact;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.analysis.testframework.BaseTest;
import org.palladiosimulator.pcm.confidentiality.context.system.SystemFactory;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.Attribute;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.DataTypes;
import org.palladiosimulator.pcm.confidentiality.context.systemcontext.SystemcontextFactory;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.ResourceEnvironment;
import org.palladiosimulator.pcm.system.System;

import edu.kit.ipd.sdq.attacksurface.graph.PCMElementType;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
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

    private CredentialChange changes;

    final protected BlackboardWrapper getBlackboardWrapper() {

        return new BlackboardWrapper(this.modification, this.assembly, this.environment, this.allocation,
                this.context.getPcmspecificationcontainer(), this.attacker.getSystemintegration(), this.eval);
    }

    protected Entity getCriticalEntity() {
        final var pcmElement = this.attacker.getAttackers()
            .getSurfaceattacker()
            .get(0)
            .getTargetedElement();
        return PCMElementType.typeOf(pcmElement)
            .getEntity(pcmElement);
    }

    protected Entity getFirstEntityByName(final String namePart) {
        final Set<Entity> allEntities = new HashSet<>(this.assembly.getAssemblyContexts__ComposedStructure());
        allEntities.addAll(this.environment.getResourceContainer_ResourceEnvironment());
        allEntities.addAll(this.environment.getLinkingResources__ResourceEnvironment());
        allEntities.addAll(this.allocation.getAllocationContexts_Allocation());
        allEntities.addAll(this.getBlackboardWrapper()
            .getVulnerabilitySpecification()
            .getVulnerabilities());
        return allEntities.stream()
            .filter(e -> e.getEntityName()
                .equals(namePart))
            .findFirst()
            .orElse(null);
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
    }

    protected UsageSpecification createContext(final String name) {
        final var contextAccess = SystemFactory.eINSTANCE.createUsageSpecification();

        final var attribute = SystemcontextFactory.eINSTANCE.createSimpleAttribute();
        final var attributeValue = SystemcontextFactory.eINSTANCE.createAttributeValue();
        attributeValue.getValues()
            .add(name);
        attributeValue.setType(DataTypes.STRING);
        attribute.getAttributevalue()
            .add(attributeValue);

        contextAccess.setEntityName(name);
        contextAccess.setAttribute(attribute);
        contextAccess.setAttributevalue(attributeValue);
        this.context.getAttributes()
            .getAttribute()
            .add(attribute);
        this.context.getPcmspecificationcontainer()
            .getUsagespecification()
            .add(contextAccess);
        return contextAccess;
    }

    protected SurfaceAttacker getSurfaceAttacker() {
        assert this.attacker.getAttackers()
            .getSurfaceattacker()
            .size() == 1;
        return this.attacker.getAttackers()
            .getSurfaceattacker()
            .get(0);
    }

    protected void createAvailabilityImpactFilter() {
        final var filterCriteria = this.getSurfaceAttacker()
            .getFiltercriteria();
        final var impactFilter = AttackerFactory.eINSTANCE.createImpactVulnerabilityFilterCriterion();
        impactFilter.setAvailabilityImpactMinimum(AvailabilityImpact.HIGH);
        filterCriteria.add(impactFilter);
    }

    protected void createCredentialFilter() {
        final var filterCriteria = this.getSurfaceAttacker()
            .getFiltercriteria();
        final var impactFilter = AttackerFactory.eINSTANCE.createInitialCredentialFilterCriterion();
        impactFilter.getProhibitedInitialCredentials()
            .add(this.createRootCredentialsIfNecessary());
        filterCriteria.add(impactFilter);
    }

    protected ContextChange toChange(final UsageSpecification credentials) {
        final var change = KAMP4attackModificationmarksFactory.eINSTANCE.createContextChange();
        change.setAffectedElement(credentials);
        change.setToolderived(true);
        return change;
    }

    protected void setCriticalResourceContainer(final String namePart) {
        final var newCriticalEntity = this.allocation.getTargetResourceEnvironment_Allocation()
            .getResourceContainer_ResourceEnvironment()
            .stream()
            .filter(r -> r.getEntityName()
                .contains(namePart))
            .findFirst()
            .orElse(null);
        if (newCriticalEntity == null) {
            throw new IllegalArgumentException("container " + namePart + " not found");
        }
        final var newCriticalElement = PcmIntegrationFactory.eINSTANCE.createPCMElement();
        newCriticalElement.setResourcecontainer(newCriticalEntity);
        final var systemInteg = PcmIntegrationFactory.eINSTANCE.createDefaultSystemIntegration();
        systemInteg.setPcmelement(newCriticalElement);
        this.attacker.getSystemintegration()
            .getVulnerabilities()
            .add(systemInteg);
        this.getSurfaceAttacker()
            .setTargetedElement(newCriticalElement);
    }

    protected void setCriticalAssemblyContext(final String namePart) {
        final var newCriticalEntity = this.assembly.getAssemblyContexts__ComposedStructure()
            .stream()
            .filter(a -> a.getEntityName()
                .contains(namePart))
            .findFirst()
            .orElse(null);
        if (newCriticalEntity == null) {
            throw new IllegalArgumentException("assembly " + namePart + " not found");
        }
        final var newCriticalElement = PcmIntegrationFactory.eINSTANCE.createPCMElement();
        newCriticalElement.getAssemblycontext()
            .add(newCriticalEntity);
        final var systemInteg = PcmIntegrationFactory.eINSTANCE.createDefaultSystemIntegration();
        systemInteg.setPcmelement(newCriticalElement);
        this.attacker.getSystemintegration()
            .getVulnerabilities()
            .add(systemInteg);
        this.getSurfaceAttacker()
            .setTargetedElement(newCriticalElement);
    }

    private UsageSpecification getRootCredentials() {
        return this.getFirstByName(ROOT_STR);
    }

    protected UsageSpecification createRootCredentialsIfNecessary() {
        if (this.getRootCredentials() == null) {
            final var root = SystemFactory.eINSTANCE.createUsageSpecification();
            root.setEntityName(ROOT_STR);
            root.setAttribute(this.createRootAttribute());
            root.setAttributevalue(root.getAttribute()
                .getAttributevalue()
                .get(0));
            this.context.getPcmspecificationcontainer()
                .getUsagespecification()
                .add(root);
        }
        return this.getRootCredentials();
    }

    private Attribute createRootAttribute() {
        final var attribute = SystemcontextFactory.eINSTANCE.createSimpleAttribute();
        attribute.setEntityName("Role");
        attribute.setEnvironment(false);
        final var value = SystemcontextFactory.eINSTANCE.createAttributeValue();
        value.getValues()
            .add(ROOT_STR);
        value.setType(DataTypes.STRING);
        attribute.getAttributevalue()
            .add(value);
        this.context.getAttributes()
            .getAttribute()
            .add(attribute);
        return attribute;
    }

    protected UsageSpecification getFirstByName(final String namePart) {
        return this.context.getPcmspecificationcontainer()
            .getUsagespecification()
            .stream()
            .filter(u -> u.getEntityName()
                .contains(namePart))
            .findFirst()
            .orElse(null);
    }

    @BeforeEach
    public void clear() {
//        resetAttackGraphAndChanges();
    }
}
