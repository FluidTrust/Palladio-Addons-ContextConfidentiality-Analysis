package org.palladiosimulator.pcm.confidentiality.context.analysis.provider;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.context.ConfidentialAccessSpecification;
import org.palladiosimulator.pcm.confidentiality.context.attacksurface.api.AttackSurfaceAnalysis;
import org.palladiosimulator.pcm.repository.Repository;

public class SurfaceImpl implements AttackSurfaceAnalysis {

    @Override
    public boolean runAttackSurfaceAnalysis(final Repository pcm, final ConfidentialAccessSpecification context,
            final Attacker adversary) {
        // TODO Auto-generated method stub
        return false;
    }

}
