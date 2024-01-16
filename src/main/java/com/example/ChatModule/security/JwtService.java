package com.example.ChatModule.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.time.Duration;
import java.util.*;




@Service
@RequiredArgsConstructor
public class JwtService {
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.lifetime}")
    private Duration jwtLifetime;

    public Claims getAllClaimsFromToken(String token) {
        System.out.println(token);
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }

    public String getUsername(String token) {
        return getAllClaimsFromToken(token).getSubject();
    }

    public List<String> getRoles(String token) {
        return getAllClaimsFromToken(token).get("role", List.class);
    }

    public String generateToken(UserDetails userDetails) {
        Date issuedDate = new Date();
        Date expiredDate = new Date(issuedDate.getTime() + jwtLifetime.toMillis());
        String role = userDetails.getAuthorities().toArray()[0].toString();
        String name = userDetails.getUsername();

        String token = JWT.create()
                .withSubject(userDetails.getUsername())
                .withIssuedAt(issuedDate)
                .withExpiresAt(expiredDate)
                .withClaim("name", name)
                .withClaim("role", role)
                .sign(Algorithm.HMAC512(secret));
        return token;
    }

//    public String getUsername(String token) {
//        if (token == null) return "";
//        return JWT.decode(token).getClaim("name").asString();
//    }
//
//    public List<String> getRoles(String token) {
//        List<String> roleList = new ArrayList<String>();
//        roleList.add(JWT.decode(token).getClaim("role").asString());
//        return roleList;
//    }

}
