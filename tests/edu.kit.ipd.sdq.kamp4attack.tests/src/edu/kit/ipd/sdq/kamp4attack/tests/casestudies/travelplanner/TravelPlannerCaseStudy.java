package edu.kit.ipd.sdq.kamp4attack.tests.casestudies.travelplanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceSpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedService;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;
import edu.kit.ipd.sdq.kamp4attack.tests.change.AbstractChangeTests;

public abstract class TravelPlannerCaseStudy extends AbstractChangeTests {

    public TravelPlannerCaseStudy() {
        this.PATH_REPOSITORY = "travelplanner/default.repository";
        this.PATH_RESOURCES = "travelplanner/default.resourceenvironment";
        this.PATH_ASSEMBLY = "travelplanner/default.system";
        this.PATH_ALLOCATION = "travelplanner/default.allocation";
    }

    @Test
    void defaultCase() {
        this.runAnalysis();
    }

    protected CredentialChange getCredentials() {
        assertEquals(1, this.modification.getChangePropagationSteps()
            .size());

        final var change = this.modification.getChangePropagationSteps()
            .get(0);

        assertTrue(change instanceof CredentialChange);

        return change;

    }

    protected boolean checkAssembly(final CredentialChange change) {
        return change.getCompromisedassembly()
            .stream()
            .map(CompromisedAssembly::getAffectedElement)
            .map(AssemblyContext::getEntityName)
            .allMatch(this::assemblyNameMatch);
    }

    protected boolean checkResource(final CredentialChange change) {
        return change.getCompromisedresource()
            .stream()
            .map(CompromisedResource::getAffectedElement)
            .map(ResourceContainer::getEntityName)
            .allMatch(this::resourceNameMatch);
    }

    protected boolean checkLining(final CredentialChange change) {
        return change.getCompromisedlinkingresource()
            .stream()
            .map(CompromisedLinkingResource::getAffectedElement)
            .map(LinkingResource::getEntityName)
            .allMatch(this::linkingResourceNameMatch);
    }

    protected boolean checkContext(final CredentialChange change) {
        return change.getContextchange()
            .stream()
            .map(ContextChange::getAffectedElement)
            .allMatch(this::checkAttributeUsage);
    }

    protected boolean checkServiceRestriction(final CredentialChange change) {
        return change.getCompromisedservice()
            .stream()
            .map(CompromisedService::getAffectedElement)
            .allMatch(this::checkServiceRestriction);
    }

    protected boolean assemblyNameMatch(final String name) {
        fail();
        return false;
    }

    protected boolean resourceNameMatch(final String name) {
        fail();
        return false;
    }

    protected boolean checkAttributeUsage(final UsageSpecification usage) {
        fail();
        return false;
    }

    protected boolean checkServiceRestriction(final ServiceSpecification servicerestriction1) {
        fail();
        return false;
    }

    protected boolean linkingResourceNameMatch(final String name) {
        fail();
        return false;
    }

}
