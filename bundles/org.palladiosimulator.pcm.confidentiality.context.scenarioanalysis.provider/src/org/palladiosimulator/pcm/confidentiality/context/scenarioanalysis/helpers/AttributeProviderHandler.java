package org.palladiosimulator.pcm.confidentiality.context.scenarioanalysis.helpers;

import java.util.List;

import org.palladiosimulator.pcm.confidentiality.context.system.AttributeProvider;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

/**
 * Class for handling {@link AttributeProvider} in the scenario anlysis. It helps to identify
 * context/credential changes during the analysis
 *
 * @author majuwa
 *
 */
public class AttributeProviderHandler {

    private final List<PCMAttributeProvider> pcmAttributeProviders;

    /**
     *
     * @param attributeProviders
     */
    public AttributeProviderHandler(final List<AttributeProvider> attributeProviders) {
        this.pcmAttributeProviders = attributeProviders.stream().filter(PCMAttributeProvider.class::isInstance)
                .map(PCMAttributeProvider.class::cast).toList();
    }

    /**
     * Searches for matching {@link AttributeProvider}s based on the {@link AssemblyConnector} and
     * the current {@link AssemblyContext}. It return a list of {@link UsageSpecification}s which
     * acts as credentials
     *
     * @param conntector
     *            the targeted Connector
     * @param assemblyContext
     *            the current assemblyContext
     * @return List with {@link UsageSpecification}, empty if no AttributeProviderExists
     */
    public List<? extends UsageSpecification> getContext(final AssemblyConnector conntector,
            final List<AssemblyContext> assemblyContext) {

        return this.pcmAttributeProviders.stream()
                .filter(provider -> this.filterMatching(provider, conntector, assemblyContext))
                .map(PCMAttributeProvider::getAttribute).toList();
    }

    private boolean filterMatching(final PCMAttributeProvider provider, final AssemblyConnector connector,
            final List<AssemblyContext> assemblyContext) {
        if (provider.getMethodspecification() == null) {
            return false;
        }
        final var specification = provider.getMethodspecification();

        return specification.getId().equals(connector.getId())
                && this.checkAssemblyList(assemblyContext, specification.getHierachy());

    }

    private boolean checkAssemblyList(final List<AssemblyContext> target, final List<AssemblyContext> compare) {
        if (target.size() != compare.size()) {
            return false;
        }
        for (var i = 0; i < target.size(); i++) {
            if (!target.get(i).getId().equals(compare.get(i).getId())) {
                return false;
            }
        }
        return true;
    }
}
