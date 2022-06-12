package edu.kit.ipd.sdq.attacksurface.tests.change.credentials;

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.attacksurface.core.AttackSurfaceAnalysis;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusEdge;
import edu.kit.ipd.sdq.attacksurface.graph.AttackStatusNodeContent;
import edu.kit.ipd.sdq.attacksurface.tests.change.AbstractChangeTests;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

class PropagationContextAssemblyTest extends AbstractChangeTests {
    private void runAssemblyToAssemblyPropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var contextChange = new AssemblyContextPropagationContext(wrapper, change, getAttackGraph());
        contextChange.calculateAssemblyContextToAssemblyContextPropagation();
    }

    private void runAssemblyAssemblyVulnerabilityPropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var assemblyChange = new AssemblyContextPropagationVulnerability(wrapper, change, getAttackGraph());
        assemblyChange.calculateAssemblyContextToAssemblyContextPropagation();
    }

    private void runAssemblyResourcePropagation(final CredentialChange change) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var assemblyChange = new AssemblyContextPropagationContext(wrapper, change, getAttackGraph());
        assemblyChange.calculateAssemblyContextToLocalResourcePropagation();
        assemblyChange.calculateAssemblyContextToRemoteResourcePropagation();
    }

    private void runResourceToLocalAssemblyPropagation(CredentialChange changes) {
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var resChange = new ResourceContainerPropagationContext(wrapper, changes, getAttackGraph());
        resChange.calculateResourceContainerToLocalAssemblyContextPropagation();
    }

    @Test
    public void compromiseCriticalAssmblyVulnerabilityThenCredentialTest() {
        final var cweid = this.createCWEID(0);
        final var vuln = createCWEVulnerability(cweid, false, true);
        final var criticalEntity = getCriticalEntity();
        final var containerOfCritical = getResource(List.of((AssemblyContext) criticalEntity));
        integrateVulnerability(criticalEntity, vuln);
        integrateRoot(containerOfCritical);

        runAssemblyAssemblyVulnerabilityPropagation(getChanges());
        runAssemblyResourcePropagation(getChanges());

        assertCompromisationStatus(true, true, containerOfCritical, createRootCredentialsIfNecessary().getId());

        assertCompromisationStatus(false, true, criticalEntity, vuln.getId());
        runResourceToLocalAssemblyPropagation(getChanges());
        assertCompromisationStatus(true, true, criticalEntity, null);
    }

    @Test
    public void compromiseCriticalComponentWithCredentialOnContainerTest() {
        final var criticalEntity = getCriticalEntity();
        final var containerOfCritical = getResource(List.of((AssemblyContext) criticalEntity));
        final var containerNodeContent = new AttackStatusNodeContent(containerOfCritical);
        integrateRoot(containerOfCritical);

        runAssemblyResourcePropagation(getChanges());

        final var rootCred = createRootCredentialsIfNecessary();
        final var rootCauseId = rootCred.getId();
        final var surfacePaths = getAttackGraph().findAllAttackPaths(getBlackboardWrapper(), getChanges());
        Assert.assertFalse(surfacePaths.isEmpty());
        surfacePaths.forEach(p -> {
            final var creds = p.toAttackPath(getBlackboardWrapper(), criticalEntity, false).getCredentialsInitiallyNecessary();
            System.out.println("creds= " + creds.size() + " | " + p);
            Assert.assertEquals(1, creds.size());
            Assert.assertEquals(rootCred.getId(), creds.get(0).getId());
            final Iterable<AttackStatusEdge> iter = p::iterator;
            final var list = new ArrayList<AttackStatusEdge>();
            iter.forEach(list::add);
            Assert.assertTrue(list.stream().anyMatch(e -> e.getNodes().target().equals(containerNodeContent)
                    && e.getContent().contains(rootCauseId)));
        });
        assertCompromisationStatus(true, true, containerOfCritical, rootCred.getId());
        assertCompromisationStatus(true, true, criticalEntity, null);
    }

    @Test
    public void filteredCriticalComponentWithCredentialOnContainerTest() {
        createCredentialFilter();
        final var criticalEntity = getCriticalEntity();
        final var containerOfCritical = getResource(List.of((AssemblyContext) criticalEntity));
        integrateRoot(containerOfCritical);

        runAssemblyResourcePropagation(getChanges());

        final var rootCred = createRootCredentialsIfNecessary();
        final var surfacePaths = getAttackGraph().findAllAttackPaths(getBlackboardWrapper(), getChanges());
        final var pathsConverter = new AttackSurfaceAnalysis(true, getBlackboardWrapper());
        final var paths = pathsConverter.toAttackPaths(surfacePaths, getBlackboardWrapper());
        Assert.assertTrue(paths.isEmpty());
    }
}
