package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import java.util.List;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.entity.Entity;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context.AssemblyContextContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context.LinkingResourceContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context.ResourceContainerContext;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class ResourceContainerPropagationContext extends ResourceContainerChange {

    public ResourceContainerPropagationContext(final BlackboardWrapper v, final CredentialChange change,
            final AttackGraph attackGraph) {
        super(v, change, attackGraph);
    }

    @Override
    protected LinkingResourceHandler getLinkingHandler() {
        return new LinkingResourceContext(this.modelStorage, new DataHandlerAttacker(this.changes), getAttackGraph());
    }

    @Override
    protected ResourceContainerHandler getResourceHandler() {
        return new ResourceContainerContext(this.modelStorage, new DataHandlerAttacker(this.changes), getAttackGraph());
    }

    @Override
    protected AssemblyContextHandler getAssemblyHandler() {
        return new AssemblyContextContext(this.modelStorage, new DataHandlerAttacker(this.changes), getAttackGraph());
    }

    @Override
    protected void handleSeff(final CredentialChange changes, final List<AssemblyContext> components,
            final ResourceContainer source) {
        // intentional blank

    }

}
