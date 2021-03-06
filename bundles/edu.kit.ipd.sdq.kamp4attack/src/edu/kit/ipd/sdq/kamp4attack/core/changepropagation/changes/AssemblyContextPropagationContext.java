package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.List;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.context.specification.assembly.ProvidedRestriction;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context.AssemblyContextContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context.LinkingResourceContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context.ResourceContainerContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class AssemblyContextPropagationContext extends AssemblyContextChange {

    public AssemblyContextPropagationContext(final BlackboardWrapper v) {
        super(v);
    }

    @Override
    protected ResourceContainerHandler getLocalResourceHandler() {
        return new ResourceContainerContext(this.modelStorage, new DataHandlerAttacker(getAttacker()));
    }

    @Override
    protected AssemblyContextHandler getAssemblyHandler() {
        return new AssemblyContextContext(this.modelStorage, new DataHandlerAttacker(getAttacker()));
    }

    @Override
    protected LinkingResourceHandler getLinkingHandler() {
        return new LinkingResourceContext(this.modelStorage, new DataHandlerAttacker(getAttacker()));
    }

    @Override
    protected ResourceContainerHandler getRemoteResourceHandler() {
        return new ResourceContainerContext(this.modelStorage, new DataHandlerAttacker(getAttacker()));
    }

    @Override
    protected void handleSeff(CredentialChange changes, List<ProvidedRestriction> components, AssemblyContext source) {
        // intentional blank
    }

}
