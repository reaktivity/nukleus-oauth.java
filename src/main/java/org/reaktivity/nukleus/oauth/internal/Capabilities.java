package org.reaktivity.nukleus.oauth.internal;

public class Capabilities
{
    private static final int CHALLENGE_MASK = 0x01;
    private static final int CHALLENGE_BIT = 1;

    private Capabilities()
    {
    }

    public static boolean canChallenge(
        int capabilities)
    {
        return (capabilities & CHALLENGE_MASK) == CHALLENGE_BIT;
    }
}
