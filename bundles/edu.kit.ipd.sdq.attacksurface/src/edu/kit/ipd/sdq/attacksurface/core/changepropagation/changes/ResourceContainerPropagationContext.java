package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context.AssemblyContextContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context.ResourceContainerContext;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.kamp4attack.core.api.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class ResourceContainerPropagationContext extends ResourceContainerChange {
    public ResourceContainerPropagationContext(final BlackboardWrapper modelStorage, final CredentialChange change,
            final AttackGraph attackGraph) {
        super(modelStorage, change, attackGraph);
    }

    @Override
    protected ResourceContainerHandler getResourceHandler() {
        return new ResourceContainerContext(this.modelStorage, new DataHandlerAttacker(this.changes), getAttackGraph());
    }

    @Override
    protected AssemblyContextHandler getAssemblyHandler() {
        return new AssemblyContextContext(this.modelStorage, new DataHandlerAttacker(this.changes), getAttackGraph());
    }

}
