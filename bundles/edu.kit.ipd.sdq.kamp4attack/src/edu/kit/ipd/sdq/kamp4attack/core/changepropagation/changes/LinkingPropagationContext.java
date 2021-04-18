package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context.AssemblyContextContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context.ResourceContainerContext;

public class LinkingPropagationContext extends LinkingChange {

    public LinkingPropagationContext(final BlackboardWrapper v) {
        super(v);
    }

    @Override
    protected ResourceContainerHandler getResourceContainerHandler() {
        return new ResourceContainerContext(this.modelStorage, new DataHandlerAttacker(this.getAttacker()));
    }

    @Override
    protected AssemblyContextHandler getAssemblyContextHandler() {
        return new AssemblyContextContext(this.modelStorage, new DataHandlerAttacker(this.getAttacker()));
    }
}
