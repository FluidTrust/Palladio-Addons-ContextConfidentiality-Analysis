package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.attacksurface.attackdag.AttackDAG;
import edu.kit.ipd.sdq.attacksurface.attackdag.AttackStatusDescriptorNodeContent;
import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context.AssemblyContextContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context.MethodContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class AssemblyContextPropagationContext extends AssemblyContextChange {
    private final AssemblyContext criticalAssemblyContext;
    
    public AssemblyContextPropagationContext(final BlackboardWrapper v, final CredentialChange changes, 
            final AssemblyContext criticalAssemblyContext) {
        super(v, changes);
        this.criticalAssemblyContext = criticalAssemblyContext;
    }
    
    @Override
    protected Collection<AssemblyContext> loadInitialMarkedItems() {
        return Arrays.asList(this.criticalAssemblyContext); //TODO ok? are this the initial items?
    }

    @Override
    protected ResourceContainerHandler getLocalResourceHandler() {
    	return null; //TODO
        //TODO return new ResourceContainerContext(this.modelStorage, new DataHandlerAttacker(getAttacker()));
    }

    @Override
    protected AssemblyContextHandler getAssemblyHandler() {
        return new AssemblyContextContext(this.modelStorage, new DataHandlerAttacker(changes));
    }

    @Override
    protected LinkingResourceHandler getLinkingHandler() {
    	return null; //TODO
        //TODO return new LinkingResourceContext(this.modelStorage, new DataHandlerAttacker(getAttacker()));
    }

    @Override
    protected ResourceContainerHandler getRemoteResourceHandler() {
    	return null; //TODO
        //TODO return new ResourceContainerContext(this.modelStorage, new DataHandlerAttacker(getAttacker()));
    }

    @Override
    protected void handleSeff(final CredentialChange changes, final List<ServiceRestriction> services,
            final AssemblyContext source) {
        final var handler = new MethodContext(this.modelStorage, new DataHandlerAttacker(changes));
        handler.attackService(services, changes, source);
    }

}
