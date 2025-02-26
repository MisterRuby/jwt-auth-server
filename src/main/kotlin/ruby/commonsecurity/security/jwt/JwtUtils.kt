package ruby.commonsecurity.security.jwt

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import jakarta.annotation.PostConstruct
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClientException
import org.springframework.web.client.RestTemplate
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey
import java.util.*

@Component
class JwtUtils(
    private val jwtProperties: JwtProperties,
    private val restTemplate: RestTemplate,
) {
    private var keyPair: KeyPair = Keys.keyPairFor(SignatureAlgorithm.RS256)
    private var privateKey: PrivateKey = keyPair.private // 서명용
    var publicKey: PublicKey = keyPair.public // 검증용

    @PostConstruct
    fun init() {
        generateKeyPair()
    }

    /**
     * keyPair 를 일정 주기로 갱신
     * - 갱신 후 연동되는 리소스 서버(resourceServersWebhook)에 생성된 공개키를 보내준다.
     */
    @Scheduled(cron = "#{@jwtProperties.generateSchedule}")
    fun generateKeyPair() {
        keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256)
        privateKey = keyPair.private // 서명용
        publicKey = keyPair.public // 검증용

        jwtProperties.resourceServersUrls.forEach { url ->
            updateResourceServerPublicKey(url)
        }
    }

    private fun updateResourceServerPublicKey(url: String): Boolean {
        // 웹훅 요청 데이터 생성
        return try {
            val jwk = getJwk()

            // 요청 헤더 설정
            val headers = HttpHeaders()
            headers.contentType = MediaType.APPLICATION_JSON

            // HttpEntity를 사용하여 요청 body와 headers를 포함함
            val requestEntity = HttpEntity(jwk, headers)

            // 요청 보내기
            restTemplate.postForEntity(url, requestEntity, String::class.java)
            true
        } catch (ex: RestClientException) {
            false
        }
    }

    fun getJwk(): Jwk {
        val publicKey = publicKey as RSAPublicKey

        // JWK 형식의 JSON 데이터 반환
        return Jwk(
            kty = "RSA",
            alg = "RS256", // 알고리즘
            use = "sig", // 용도 (서명)
            n = Base64.getUrlEncoder().encodeToString(publicKey.modulus.toByteArray()), // modulus
            e = Base64.getUrlEncoder().encodeToString(publicKey.publicExponent.toByteArray()) // exponent
        )
    }

    fun generateToken(email: String): String {
        return Jwts.builder()
            .setSubject(email)
            .setIssuedAt(Date())
            .setExpiration(Date(System.currentTimeMillis() + jwtProperties.accessTokenExpirationMs))
            .signWith(privateKey, SignatureAlgorithm.RS256)
            .compact()
    }

    fun validateToken(token: String): Boolean {
        return try {
            Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(token)
            true
        } catch (ex: Exception) {
            false
        }
    }

    fun getUsernameFromToken(token: String): String {
        val claims = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(token).body
        return claims.subject
    }
}

@Component
@ConfigurationProperties(prefix = "jwt")
class JwtProperties {
    var accessTokenExpirationMs: Int = 15 * 60 * 1000 // 15분
    var refreshTokenExpirationMs: Int = 7 * 24 * 60 * 60 * 1000 // 7일
    var generateSchedule: String = "0 0 0 1 * *"
    var resourceServersUrls: List<String> = emptyList()
}

data class Jwk(val kty: String, val alg: String, val use: String, val n: String, val e: String)
