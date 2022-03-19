package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.List;

import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;
import org.palladiosimulator.pcm.resourceenvironment.LinkingResource;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context.AssemblyContextContext;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context.ResourceContainerContext;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class LinkingPropagationContext extends LinkingChange {

    public LinkingPropagationContext(final BlackboardWrapper v, CredentialChange change) {
        super(v, change);
    }

    @Override
    protected ResourceContainerHandler getResourceContainerHandler() {
        return new ResourceContainerContext(this.modelStorage, new DataHandlerAttacker(this.changes));
    }

    @Override
    protected AssemblyContextHandler getAssemblyContextHandler() {
        return new AssemblyContextContext(this.modelStorage, new DataHandlerAttacker(this.changes));
    }

    @Override
    protected void handleSeff(final CredentialChange change, final List<AssemblyContextDetail> components,
            final LinkingResource source) {
        // intentional blank

    }

}
