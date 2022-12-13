package org.palladiosimulator.pcm.confidentiality.attacker.analysis.rollout.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.generator.fluent.repository.api.Repo;
import org.palladiosimulator.generator.fluent.repository.factory.FluentRepositoryFactory;
import org.palladiosimulator.generator.fluent.system.api.ISystem;
import org.palladiosimulator.generator.fluent.system.factory.FluentSystemFactory;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.rollout.RolloutImpl;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackSpecificationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.NonGlobalCommunication;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PcmIntegrationFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.RoleSystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.SystemIntegration;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.VulnerabilitySystemIntegration;
import org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.api.PCMBlackBoard;
import org.palladiosimulator.pcm.repository.RepositoryComponent;

class RolloutTest {
    private Repo repo;
    private FluentRepositoryFactory repositoryFactory;
    private FluentSystemFactory systemFactory;
    private ISystem system;

    @BeforeEach
    void prepare() {
        this.repositoryFactory = new FluentRepositoryFactory();
        this.systemFactory = new FluentSystemFactory();
        this.repo = this.repositoryFactory.newRepository();
        this.system = this.systemFactory.newSystem();
    }

    @Test
    void testRollOutVulnerability() {

        this.repo.addToRepository(this.repositoryFactory.newBasicComponent()
            .withName("Test"));
        this.system.addRepository(this.repo.createRepositoryNow());

        this.system.addToSystem(this.systemFactory.newAssemblyContext()
            .withEncapsulatedComponent("Test"));

        final var component = this.repositoryFactory.fetchOfComponent("Test");

        final var integration = List.of(this.createVulnerabilityIntegration(component, "TestVulnerability"));

        final var blackboard = new PCMBlackBoard(this.system.createSystemNow(), this.repo.createRepositoryNow(), null);

        final var roll = new RolloutImpl();

        final var out = roll.rollOut(blackboard, integration);

        assertTrue(out.get(0) instanceof VulnerabilitySystemIntegration);
        assertTrue(out.stream()
            .allMatch(e -> e.getPcmelement()
                .getBasiccomponent() == null));
        assertEquals(1, out.size());
        assertEquals("TestVulnerability", ((VulnerabilitySystemIntegration) out.get(0)).getVulnerability()
            .getEntityName());
        assertEquals(this.system.createSystemNow()
            .getAssemblyContexts__ComposedStructure()
            .get(0)
            .getId(),
                out.get(0)
                    .getPcmelement()
                    .getAssemblycontext()
                    .get(0)
                    .getId());

    }

    @Test
    void testRollOutRole() {

        this.repo.addToRepository(this.repositoryFactory.newBasicComponent()
            .withName("Test"));
        this.system.addRepository(this.repo.createRepositoryNow());

        this.system.addToSystem(this.systemFactory.newAssemblyContext()
            .withEncapsulatedComponent("Test"));

        final var component = this.repositoryFactory.fetchOfComponent("Test");

        final var integration = List.of(this.createRoleIntegration(component, "TestVulnerability"));

        final var blackboard = new PCMBlackBoard(this.system.createSystemNow(), this.repo.createRepositoryNow(), null);

        final var roll = new RolloutImpl();

        final var out = roll.rollOut(blackboard, integration);

        assertTrue(out.get(0) instanceof RoleSystemIntegration);
        assertTrue(out.stream()
            .allMatch(e -> e.getPcmelement()
                .getBasiccomponent() == null));
        assertEquals(1, out.size());
        assertEquals("TestVulnerability", ((RoleSystemIntegration) out.get(0)).getRole()
            .getEntityName());
        assertEquals(this.system.createSystemNow()
            .getAssemblyContexts__ComposedStructure()
            .get(0)
            .getId(),
                out.get(0)
                    .getPcmelement()
                    .getAssemblycontext()
                    .get(0)
                    .getId());

    }

    @Test
    void testRollOutNonglobalCommunication() {

        this.repo.addToRepository(this.repositoryFactory.newBasicComponent()
            .withName("Test"));
        this.system.addRepository(this.repo.createRepositoryNow());

        this.system.addToSystem(this.systemFactory.newAssemblyContext()
            .withEncapsulatedComponent("Test"));

        final var component = this.repositoryFactory.fetchOfComponent("Test");

        final var integration = List.of(this.createNonGlobal(component, "TestVulnerability"));

        final var blackboard = new PCMBlackBoard(this.system.createSystemNow(), this.repo.createRepositoryNow(), null);

        final var roll = new RolloutImpl();

        final var out = roll.rollOut(blackboard, integration);

        assertTrue(out.get(0) instanceof NonGlobalCommunication);
        assertTrue(out.stream()
            .allMatch(e -> e.getPcmelement()
                .getBasiccomponent() == null));
        assertEquals(1, out.size());
        assertEquals(this.system.createSystemNow()
            .getAssemblyContexts__ComposedStructure()
            .get(0)
            .getId(),
                out.get(0)
                    .getPcmelement()
                    .getAssemblycontext()
                    .get(0)
                    .getId());

    }

    /**
     * Tests whether there will be no changes if the integration is not for the Repository component
     */
    @Test
    void testNoRollOut() {

        this.repo.addToRepository(this.repositoryFactory.newBasicComponent()
            .withName("Test"));
        this.system.addRepository(this.repo.createRepositoryNow());

        this.system.addToSystem(this.systemFactory.newAssemblyContext()
            .withEncapsulatedComponent("Test"));

        final var component = this.repositoryFactory.fetchOfComponent("Test");

        final var integration = List.of(this.createVulnerabilityIntegration(component, "TestVulnerability"));
        // set vulnerability to assembly context
        integration.get(0)
            .getPcmelement()
            .setBasiccomponent(null);
        integration.get(0)
            .getPcmelement()
            .getAssemblycontext()
            .add(this.system.createSystemNow()
                .getAssemblyContexts__ComposedStructure()
                .get(0));

        final var blackboard = new PCMBlackBoard(this.system.createSystemNow(), this.repo.createRepositoryNow(), null);

        final var roll = new RolloutImpl();

        final var out = roll.rollOut(blackboard, integration);

        assertTrue(out.get(0) instanceof VulnerabilitySystemIntegration);
        assertTrue(out.stream()
            .allMatch(e -> e.getPcmelement()
                .getBasiccomponent() == null));
        assertEquals(1, out.size());
        assertEquals("TestVulnerability", ((VulnerabilitySystemIntegration) out.get(0)).getVulnerability()
            .getEntityName());
        assertEquals(this.system.createSystemNow()
            .getAssemblyContexts__ComposedStructure()
            .get(0)
            .getId(),
                out.get(0)
                    .getPcmelement()
                    .getAssemblycontext()
                    .get(0)
                    .getId());

    }

    private SystemIntegration createNonGlobal(final RepositoryComponent component, final String roleNameName) {
        final var pcmELement = PcmIntegrationFactory.eINSTANCE.createPCMElement();
        pcmELement.setBasiccomponent(component);

        final var systemIntegration = PcmIntegrationFactory.eINSTANCE.createNonGlobalCommunication();
        systemIntegration.setPcmelement(pcmELement);
        return systemIntegration;
    }

    private SystemIntegration createRoleIntegration(final RepositoryComponent component, final String roleNameName) {
        final var pcmELement = PcmIntegrationFactory.eINSTANCE.createPCMElement();
        pcmELement.setBasiccomponent(component);

        final var systemIntegration = PcmIntegrationFactory.eINSTANCE.createRoleSystemIntegration();
        systemIntegration.setPcmelement(pcmELement);
        systemIntegration.setRole(AttackSpecificationFactory.eINSTANCE.createRole());
        if (roleNameName != null) {
            systemIntegration.getRole()
                .setEntityName(roleNameName);
        }
        return systemIntegration;
    }

    private SystemIntegration createVulnerabilityIntegration(final RepositoryComponent component,
            final String vulnerabilityName) {
        final var pcmELement = PcmIntegrationFactory.eINSTANCE.createPCMElement();
        pcmELement.setBasiccomponent(component);

        final var systemIntegration = PcmIntegrationFactory.eINSTANCE.createVulnerabilitySystemIntegration();
        systemIntegration.setPcmelement(pcmELement);
        systemIntegration.setVulnerability(AttackSpecificationFactory.eINSTANCE.createCVEVulnerability());
        if (vulnerabilityName != null) {
            systemIntegration.getVulnerability()
                .setEntityName(vulnerabilityName);
        }
        return systemIntegration;
    }

}
