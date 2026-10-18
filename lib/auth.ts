import { PrivyClient, type AuthTokenClaims } from '@privy-io/server-auth'
import { prisma } from '@/lib/db'

const privy = new PrivyClient(
  process.env.NEXT_PUBLIC_PRIVY_APP_ID!,
  process.env.PRIVY_APP_SECRET!
)

export async function verifyAuthToken(token: string): Promise<AuthTokenClaims | null> {
  try {
    const claims = await privy.verifyAuthToken(token)
    if (!claims.sessionId) return claims

    const user = await prisma.user.findUnique({
      where: { privyId: claims.userId },
      select: { id: true },
    })
    if (!user) return claims

    const session = await prisma.userSession.upsert({
      where: { providerSessionId: claims.sessionId },
      create: {
        providerSessionId: claims.sessionId,
        userId: user.id,
        tokenHint: claims.sessionId.slice(-12),
      },
      update: { lastSeenAt: new Date() },
      select: { userId: true, revokedAt: true },
    })
    if (session.userId !== user.id || session.revokedAt) return null

    return claims
  } catch {
    return null
  }
}
