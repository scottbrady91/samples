import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.security.interfaces.ECPrivateKey
import java.time.Instant
import java.util.*

fun main() {
    // create EC Key
    val key: ECKey = generateECKey("123")

    // create signed JWT
    val jwt: String = createJws(key.keyID, key.toECPrivateKey())
    println(jwt)

    // validate signature (and only signature)
    val isValid: Boolean = SignedJWT
        .parse(jwt)
        .verify(ECDSAVerifier(key.toECPublicKey()))
    println("Valid signature: $isValid")
}

fun generateECKey(keyID: String): ECKey {
    return ECKeyGenerator(Curve.P_256K)
        .keyID(keyID)
        .generate()
}

fun createJws(keyID: String, key: ECPrivateKey): String {
    val header = JWSHeader.Builder(JWSAlgorithm.ES256K)
        .type(JOSEObjectType.JWT)
        .keyID(keyID)
        .build();

    val payload = JWTClaimsSet.Builder()
        .issuer("me")
        .audience("you")
        .subject("bob")
        .expirationTime(Date.from(Instant.now().plusSeconds(120)))
        .build()

    val signedJWT = SignedJWT(header, payload)
    signedJWT.sign(ECDSASigner(key))
    return signedJWT.serialize()
}