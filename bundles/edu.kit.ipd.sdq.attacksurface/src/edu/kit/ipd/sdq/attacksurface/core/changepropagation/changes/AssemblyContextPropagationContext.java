package edu.kit.ipd.sdq.attacksurface.core.changepropagation.changes;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;

import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context.AssemblyContextContext;
import edu.kit.ipd.sdq.attacksurface.core.changepropagation.attackhandlers.context.ResourceContainerContext;
import edu.kit.ipd.sdq.attacksurface.graph.AttackGraph;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class AssemblyContextPropagationContext extends AssemblyContextChange {
    
    public AssemblyContextPropagationContext(final BlackboardWrapper v, final CredentialChange changes, 
            final AttackGraph attackGraph) {
        super(v, changes, attackGraph);
    }

    @Override
    protected ResourceContainerHandler getLocalResourceHandler() {
    	return new ResourceContainerContext(this.modelStorage, new DataHandlerAttacker(this.changes), getAttackGraph());
    }

    @Override
    protected AssemblyContextHandler getAssemblyHandler() {
        return new AssemblyContextContext(this.modelStorage, new DataHandlerAttacker(this.changes), getAttackGraph());
    }

    @Override
    protected ResourceContainerHandler getRemoteResourceHandler() {
    	return new ResourceContainerContext(this.modelStorage, new DataHandlerAttacker(this.changes), getAttackGraph());
    }

}
