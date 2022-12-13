package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.List;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.DatamodelAttacker;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceSpecification;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedData;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedLinkingResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedService;

public class ChangesDTO {

    private volatile boolean changed;

    private final ChangesStorage<CompromisedAssembly, AssemblyContext> assemblies = new ChangesStorage<>();
    private final ChangesStorage<CompromisedLinkingResource, LinkingResource> linkingResources = new ChangesStorage<>();
    private final ChangesStorage<CompromisedResource, ResourceContainer> resourceContainers = new ChangesStorage<>();
    private final ChangesStorage<CompromisedService, ServiceSpecification> services = new ChangesStorage<>();
    private final ChangesStorage<CompromisedData, DatamodelAttacker> data = new ChangesStorage<>();

    public final ChangesStorage<CompromisedAssembly, AssemblyContext> getAssemblies() {
        return this.assemblies;
    }

    public final ChangesStorage<CompromisedLinkingResource, LinkingResource> getLinkingResources() {
        return this.linkingResources;
    }

    public final ChangesStorage<CompromisedResource, ResourceContainer> getResourceContainers() {
        return this.resourceContainers;
    }

    public final ChangesStorage<CompromisedService, ServiceSpecification> getServices() {
        return this.services;
    }

    public void setChanged() {
        this.changed = true;
    }

    public void addData(final List<DatamodelAttacker> data) {

    }

}
