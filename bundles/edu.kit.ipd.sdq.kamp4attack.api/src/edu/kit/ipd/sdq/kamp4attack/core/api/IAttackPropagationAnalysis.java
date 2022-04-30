package edu.kit.ipd.sdq.kamp4attack.core.api;

/**
 * Entry point for an attack propagation
 *
 * @author majuwa
 * @author ugnwq
 */
public interface IAttackPropagationAnalysis {
    void runChangePropagationAnalysis(final BlackboardWrapper board);
}
