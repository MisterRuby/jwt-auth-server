package ruby.commonsecurity.security.jwt

import io.jsonwebtoken.Jwts
import jakarta.annotation.PostConstruct
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.client.RestTemplate
import org.springframework.web.filter.OncePerRequestFilter
import ruby.commonsecurity.security.CustomUserDetailsService
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.RSAPublicKeySpec
import java.util.Base64.Decoder
import java.util.Base64.getUrlDecoder

@Component
class JwtUtils(
    private val restTemplate: RestTemplate
){
    private var publicKey: PublicKey? = null

    /**
     * 애플리케이션 실행 시 인증 서버로부터 jwk 를 요청
     */
    @PostConstruct
    fun getPublicKey() {
        val jwkResponse = restTemplate.getForEntity("http://localhost:8080/jwk", Jwk::class.java)
        if (jwkResponse.statusCode.is2xxSuccessful) {
            val jwk = jwkResponse.body!!
            generatePublicKey(jwk)
        } else {
            throw RuntimeException("Failed to fetch public key")
        }
    }

    fun generatePublicKey(jwk: Jwk) {
        // Base64 URL Decoder 생성
        val decoder: Decoder = getUrlDecoder()

        // JWK의 modulus(n)와 exponent(e)를 디코딩한 후 BigInteger로 변환
        val modulus = BigInteger(1, decoder.decode(jwk.n)) //(Base64 디코딩된 n)
        val exponent = BigInteger(1, decoder.decode(jwk.e)) //Base64 디코딩된 e

        // RSA 공개키 스펙 생성
        val publicKeySpec = RSAPublicKeySpec(modulus, exponent)

        // KeyFactory를 통해 PublicKey 객체 생성
        val keyFactory = KeyFactory.getInstance("RSA") // JWK의 kty에 따라 알고리즘 변경 가능
        publicKey = keyFactory.generatePublic(publicKeySpec)
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
class JwtAuthenticationFilter(
    private val jwtUtils: JwtUtils,
    private val userDetailsService: CustomUserDetailsService
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val authHeader = request.getHeader("Authorization")
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            val jwt = authHeader.substring(7)
            if (jwtUtils.validateToken(jwt)) {
                val username = jwtUtils.getUsernameFromToken(jwt)
                val userDetails = userDetailsService.loadUserByUsername(username)
                val authToken = UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.authorities
                )
                authToken.details = WebAuthenticationDetailsSource().buildDetails(request)
                SecurityContextHolder.getContext().authentication = authToken
            }
        }
        filterChain.doFilter(request, response)
    }
}

data class Jwk(val kty: String, val alg: String, val use: String, val n: String, val e: String)
