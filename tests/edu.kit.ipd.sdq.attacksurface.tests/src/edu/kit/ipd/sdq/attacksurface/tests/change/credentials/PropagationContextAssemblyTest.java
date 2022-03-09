package edu.kit.ipd.sdq.attacksurface.tests.change.credentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.junit.Assert;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.attacksurface.tests.change.AbstractChangeTests;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.AssemblyContextPropagationVulnerability;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes.ResourceContainerPropagationContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksFactory;

class PropagationContextAssemblyTest extends AbstractChangeTests {
    private void runAssemblyToContextPropagation(final CredentialChange change) { //TODO: adapt to context --> define what it should do
        generateXML();
        final var wrapper = getBlackboardWrapper();
        final var contextChange = new AssemblyContextPropagationContext(wrapper, change, getAttackGraph());
        contextChange.calculateAssemblyContextToContextPropagation();
    }
    
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
        final var containerOfCritical = getResource((AssemblyContext) criticalEntity);
        integrateVulnerability(criticalEntity, vuln);
        integrateRoot(containerOfCritical);

        runAssemblyAssemblyVulnerabilityPropagation(getChanges());
        runAssemblyResourcePropagation(getChanges());
        runAssemblyToContextPropagation(getChanges());
        
        assertCompromisationStatus(true, true, containerOfCritical, createRootCredentialsIfNecessary().getId());
        
        assertCompromisationStatus(false, true, criticalEntity, vuln.getId());
        runResourceToLocalAssemblyPropagation(getChanges());
        assertCompromisationStatus(true, true, criticalEntity, null);
    }
    
    @Test
    public void compromiseCriticalComponentWithCredentialOnContainerTest() {
        final var criticalEntity = getCriticalEntity();
        final var containerOfCritical = getResource((AssemblyContext) criticalEntity);
        integrateRoot(containerOfCritical);

        runAssemblyResourcePropagation(getChanges());
        runAssemblyToContextPropagation(getChanges());
        
        final var rootCred = createRootCredentialsIfNecessary();
        final var surfacePaths = this.getAttackGraph().findAllAttackPaths(getBlackboardWrapper(), getChanges());
        surfacePaths.forEach(p -> {
            final var creds = p.toAttackPath(getBlackboardWrapper(), criticalEntity, false).getCredentialsInitiallyNecessary();
            Assert.assertEquals(1, creds.size());
            Assert.assertEquals(rootCred.getId(), creds.get(0).getId());
        });
        assertCompromisationStatus(true, true, containerOfCritical, rootCred.getId());
        assertCompromisationStatus(true, true, criticalEntity, null);
    }
}
