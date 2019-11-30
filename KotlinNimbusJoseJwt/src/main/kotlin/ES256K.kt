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
import java.time.Instant
import java.util.*

fun main() {
    // create EC key
    val key: ECKey = ECKeyGenerator(Curve.P_256K)
        .keyID("123")
        .generate()

    // create signed JWT
    val header = JWSHeader.Builder(JWSAlgorithm.ES256K)
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
    signedJWT.sign(ECDSASigner(key.toECPrivateKey()))

    val jwt: String = signedJWT.serialize()
    println(jwt)

    // validate signature (and only signature)
    val isValid: Boolean = SignedJWT
        .parse(jwt)
        .verify(ECDSAVerifier(key.toECPublicKey()))
    println("Valid signature: $isValid")
}