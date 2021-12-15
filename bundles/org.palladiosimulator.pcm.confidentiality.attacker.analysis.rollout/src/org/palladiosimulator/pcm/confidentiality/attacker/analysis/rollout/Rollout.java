package org.palladiosimulator.pcm.confidentiality.attacker.analysis.rollout;


public interface Rollout<T, E> {

    E rollOut(T t, E e);

}
