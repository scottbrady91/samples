import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.time.Instant
import java.util.*

fun main() {
    val key: OctetKeyPair = OctetKeyPairGenerator(Curve.Ed25519)
        .keyID("123")
        .generate()

    val header = JWSHeader.Builder(JWSAlgorithm.EdDSA)
        .type(JOSEObjectType.JWT)
        .keyID(key.keyID)
        .build();
    val payload = JWTClaimsSet.Builder()
        .issuer("me")
        .audience("you")
        .subject("bob")
        .expirationTime(Date.from(Instant.now().plusSeconds(120)))
        .build()

    val signedJWT = SignedJWT(header, payload)
    signedJWT.sign(Ed25519Signer(key))

    val jwt: String = signedJWT.serialize()
    println(jwt)


    // validate signature (and only signature)
    val isValid: Boolean = SignedJWT
        .parse(jwt)
        .verify(Ed25519Verifier(key.toPublicJWK()))
    println("Valid signature: $isValid")
}