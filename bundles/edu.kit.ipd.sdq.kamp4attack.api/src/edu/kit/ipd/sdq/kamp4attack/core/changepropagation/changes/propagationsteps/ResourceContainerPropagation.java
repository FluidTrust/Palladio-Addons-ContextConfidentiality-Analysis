package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps;

/**
 * Interface for attacker propagation from a compromised resource container
 *
 * @author majuwa
 *
 */
public interface ResourceContainerPropagation {

    void calculateResourceContainerToContextPropagation();

    void calculateResourceContainerToRemoteAssemblyContextPropagation();

    void calculateResourceContainerToLocalAssemblyContextPropagation();

    void calculateResourceContainerToResourcePropagation();

    void calculateResourceContainerToLinkingResourcePropagation();

}
