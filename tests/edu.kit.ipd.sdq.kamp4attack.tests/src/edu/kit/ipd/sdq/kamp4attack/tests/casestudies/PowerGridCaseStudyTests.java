package edu.kit.ipd.sdq.kamp4attack.tests.casestudies;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

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
import edu.kit.ipd.sdq.kamp4attack.tests.change.AbstractChangeTests;

public class PowerGridCaseStudyTests extends AbstractChangeTests {

    public PowerGridCaseStudyTests() {
        this.PATH_ATTACKER = "powerGrid/My.attacker";
        this.PATH_ASSEMBLY = "powerGrid/powerGrid.system";
        this.PATH_ALLOCATION = "powerGrid/powerGrid.allocation";
        this.PATH_CONTEXT = "powerGrid/My.context";
        this.PATH_MODIFICATION = "powerGrid/My.kamp4attackmodificationmarks";
        this.PATH_REPOSITORY = "powerGrid/target.repository";
        this.PATH_RESOURCES = "powerGrid/powerGrid.resourceenvironment";
    }

    @Test
    void defaultCase() {

        this.runAnalysis();
    }

    @Test
    void defaultCaseCorrectAssemblyNumber() {
        this.runAnalysis();
        final var change = this.modification.getChangePropagationSteps()
            .get(0);
        assertEquals(5, change.getCompromisedresource()
            .size());
        assertEquals(9, change.getCompromisedassembly()
            .size());
        assertEquals(10, change.getCompromisedservice()
            .size());
        assertEquals(4, change.getContextchange()
            .size());
        assertEquals(1, change.getCompromisedlinkingresource()
            .size());

        final var containsRequiredAssemblies = change.getCompromisedassembly()
            .stream()
            .map(CompromisedAssembly::getAffectedElement)
            .map(AssemblyContext::getEntityName)
            .allMatch(this::assemblyNameMatch);

        final var containsRequiredResources = change.getCompromisedresource()
            .stream()
            .map(CompromisedResource::getAffectedElement)
            .map(ResourceContainer::getEntityName)
            .allMatch(this::resourceNameMatch);

        final var containsRequiredLinking = change.getCompromisedlinkingresource()
            .stream()
            .map(CompromisedLinkingResource::getAffectedElement)
            .map(LinkingResource::getEntityName)
            .allMatch(this::linkingNameMatch);

        final var containsRequiredContext = change.getContextchange()
            .stream()
            .map(ContextChange::getAffectedElement)
            .allMatch(this::checkAttribute);

        change.getCompromisedservice()
            .stream()
            .map(CompromisedService::getAffectedElement)
            .allMatch(this::checkServiceRestriction);

        assertTrue(containsRequiredAssemblies);
        assertTrue(containsRequiredResources);
        assertTrue(containsRequiredLinking);
        assertTrue(containsRequiredContext);

    }

    private boolean assemblyNameMatch(final String name) {
        final var set = Set.of("Assembly_StorageApplication", "Assembly_CallCenterApplication", "ICS-VPN-Bridge",
                "AssemblyWithVPNRights", "Assembly_DomainControler", "AssemblyWithoutRights", "ExternalVPNBridge",
                "Assembly_DMSClientApplication", "Assembly_DMSServerApplication");
        return set.contains(name);
    }

    private boolean resourceNameMatch(final String name) {
        final var set = Set.of("Workstation01", "CallCenter", "DataCenter", "Workstation02", "VPNBridgeExternal");
        return set.contains(name);
    }

    private boolean linkingNameMatch(final String name) {
        final var set = Set.of("CorporateNetwork");
        return set.contains(name);
    }

    private boolean checkAttribute(final UsageSpecification specification) {
        final var attributeEquals = specification.getAttribute()
            .getId()
            .equals("_8fjUoi8jEeylPOrRpUZy4w");
        if (!attributeEquals) {
            return attributeEquals;
        }
        final var set = Set.of("_-E3soC8jEeylPOrRpUZy4w", "_CkwYUC8kEeylPOrRpUZy4w", "_GNARYC8kEeylPOrRpUZy4w",
                "_XsEwUC8kEeylPOrRpUZy4w");
        return set.contains(specification.getAttributevalue()
            .getId());
    }

    private boolean checkServiceRestriction(final ServiceSpecification restriction) {
        final var setAssembly = Set.of("Assembly_StorageApplication", "Assembly_CallCenterApplication",
                "ICS-VPN-Bridge", "AssemblyWithVPNRights", "Assembly_DomainControler", "AssemblyWithoutRights",
                "Assembly_DMSClientApplication", "Assembly_DMSServerApplication", "ExternalVPNBridge");

        final var equalAssembly = setAssembly.contains(restriction.getAssemblycontext()
            .getEntityName());
        if (!equalAssembly) {
            return equalAssembly;
        }
        final var setServices = Set.of("_Q-7lUCwjEeylP6vhO63XvA", "_xXMikCwiEeylP6vhO63XvA", "_B6cScCwjEeylP6vhO63XvA",
                "_9onQ4CwiEeylP6vhO63XvA", "_xWrqQC2YEeyiUoiCEbquLw", "_G-t3wC2bEeyiUoiCEbquLw",
                "_ZHSHAC2YEeyiUoiCEbquLw", "_ZIvfkC2YEeyiUoiCEbquLw");
        return setServices.contains(restriction.getService()
            .getId());

    }
}
