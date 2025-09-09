package com.example.crimealert;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import jakarta.persistence.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.io.IOException;
import java.security.Key;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.*;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/** ===================== BOOT ===================== **/
@SpringBootApplication
public class CrimeAlertApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrimeAlertApplication.class, args);
    }

    // Optional demo seed so the app "has life" on first run
    @Bean CommandLineRunner seed(UserRepository users, IncidentRepository incidents) {
        return args -> {
            if (users.count() == 0) {
                var enc = new BCryptPasswordEncoder();
                User admin = new User(null, "Admin User", "admin@example.com",
                        enc.encode("Admin123!"), Role.ADMIN, null, null, new HashSet<>(Set.of("CRIME","FIRE")));
                users.save(admin);
            }
            if (incidents.count() == 0) {
                incidents.save(Incident.newIncident(
                        IncidentType.CRIME, "Street mugging", "Phone taken at traffic light",
                        -26.2041, 28.0473, 1L));
            }
        };
    }
}

/** ===================== SECURITY ===================== **/
@Configuration
class SecurityConfig {

    private final JwtAuthFilter jwtFilter;
    public SecurityConfig(JwtAuthFilter jwtFilter) { this.jwtFilter = jwtFilter; }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(c -> {})                               // if you added CorsConfig
                .csrf(cs -> cs.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // public pages
                        .requestMatchers("/", "/index.html").permitAll()
                        // Swagger / OpenAPI
                        .requestMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                        // H2 console (dev)
                        .requestMatchers("/h2-console/**").permitAll()
                        // auth + health
                        .requestMatchers("/api/auth/**", "/actuator/health").permitAll()
                        // everything else requires JWT
                        .anyRequest().authenticated()
                )
                .headers(h -> h.frameOptions(f -> f.sameOrigin())) // H2 console
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}

@Component
class JwtAuthFilter extends org.springframework.web.filter.OncePerRequestFilter {
    private final JwtService jwt;
    private final UserRepository users;

    JwtAuthFilter(JwtService jwt, UserRepository users) { this.jwt = jwt; this.users = users; }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String header = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                String email = jwt.getSubject(token);
                Optional<User> userOpt = users.findByEmail(email);
                if (userOpt.isPresent()) {
                    var role = userOpt.get().getRole();
                    var auth = new UsernamePasswordAuthenticationToken(
                            email, null, List.of(new SimpleGrantedAuthority("ROLE_" + role.name())));
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } catch (Exception ignored) { }
        }
        chain.doFilter(req, res);
    }
}

@Service
class JwtService {
    // CHANGE THIS IN REAL PROJECTS (use 256-bit+)
    private static final String SECRET = "change-me-change-me-change-me-change-me-256-bits!!!";
    private static final long EXP_MIN = 120;
    private final Key key = Keys.hmacShaKeyFor(SECRET.getBytes());

    String generate(String subject, Map<String, Object> claims) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(subject)
                .addClaims(claims)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(EXP_MIN * 60)))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
    String getSubject(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody().getSubject();
    }
}

/** ===================== AUTH ===================== **/
@RestController
@RequestMapping("/api/auth")
@Validated
class AuthController {
    private final AuthService service;
    AuthController(AuthService service) { this.service = service; }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest req) {
        return ResponseEntity.ok(service.register(req));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest req) {
        return ResponseEntity.ok(service.login(req));
    }
}

@Service
class AuthService {
    private final UserRepository users;
    private final JwtService jwt;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    AuthService(UserRepository users, JwtService jwt) { this.users = users; this.jwt = jwt; }

    AuthResponse register(RegisterRequest req) {
        if (users.existsByEmail(req.getEmail())) throw new IllegalArgumentException("Email already in use");
        User user = new User(null, req.getFullName(), req.getEmail(),
                encoder.encode(req.getPassword()), Role.USER, null, null, new HashSet<>());
        users.save(user);
        String token = jwt.generate(user.getEmail(), Map.of("role", user.getRole().name()));
        return new AuthResponse(token);
    }

    AuthResponse login(LoginRequest req) {
        User user = users.findByEmail(req.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));
        if (!encoder.matches(req.getPassword(), user.getPasswordHash()))
            throw new IllegalArgumentException("Invalid credentials");
        String token = jwt.generate(user.getEmail(), Map.of("role", user.getRole().name()));
        return new AuthResponse(token);
    }
}

class RegisterRequest {
    @NotBlank private String fullName;
    @Email @NotBlank private String email;
    @NotBlank @Size(min = 6) private String password;
    public String getFullName() { return fullName; }
    public String getEmail() { return email; }
    public String getPassword() { return password; }
}
class LoginRequest {
    @Email @NotBlank private String email;
    @NotBlank private String password;
    public String getEmail() { return email; }
    public String getPassword() { return password; }
}
class AuthResponse {
    private String token;
    public AuthResponse() { }
    public AuthResponse(String token) { this.token = token; }
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
}

/** ===================== USER / JPA ===================== **/
enum Role { USER, ADMIN }

@Entity
@Table(name = "users")
class User {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable=false) private String fullName;
    @Column(nullable=false, unique=true) private String email;
    @Column(nullable=false) private String passwordHash;

    @Enumerated(EnumType.STRING) @Column(nullable=false)
    private Role role;

    private Double homeLat;
    private Double homeLng;

    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> alertCategories = new HashSet<>();

    public User() {}
    public User(Long id, String fullName, String email, String passwordHash, Role role,
                Double homeLat, Double homeLng, Set<String> alertCategories) {
        this.id = id; this.fullName = fullName; this.email = email; this.passwordHash = passwordHash;
        this.role = role; this.homeLat = homeLat; this.homeLng = homeLng;
        if (alertCategories != null) this.alertCategories = alertCategories;
    }

    public Long getId() { return id; }
    public String getFullName() { return fullName; }
    public String getEmail() { return email; }
    public String getPasswordHash() { return passwordHash; }
    public Role getRole() { return role; }
    public Double getHomeLat() { return homeLat; }
    public Double getHomeLng() { return homeLng; }
    public Set<String> getAlertCategories() { return alertCategories; }
    public void setId(Long id) { this.id = id; }
    public void setFullName(String fullName) { this.fullName = fullName; }
    public void setEmail(String email) { this.email = email; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    public void setRole(Role role) { this.role = role; }
    public void setHomeLat(Double homeLat) { this.homeLat = homeLat; }
    public void setHomeLng(Double homeLng) { this.homeLng = homeLng; }
    public void setAlertCategories(Set<String> alertCategories) { this.alertCategories = alertCategories; }
}

interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);
}

/** ===================== INCIDENTS ===================== **/
enum IncidentType { CRIME, FIRE, MEDICAL, TRAFFIC, OTHER }

@Embeddable
class GeoPoint {
    private Double lat;
    private Double lng;
    public GeoPoint() {}
    public GeoPoint(Double lat, Double lng) { this.lat = lat; this.lng = lng; }
    public Double getLat() { return lat; }
    public Double getLng() { return lng; }
    public void setLat(Double lat) { this.lat = lat; }
    public void setLng(Double lng) { this.lng = lng; }
}

@Entity
class Incident {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING) @Column(nullable=false)
    private IncidentType type;

    @Embedded
    private GeoPoint location;

    @Column(nullable=false) private String title;
    @Column(length=2000) private String description;

    @Column(nullable=false) private OffsetDateTime reportedAt;
    @Column(nullable=false) private Long reporterUserId;

    private String status; // OPEN, VERIFIED, RESOLVED

    public Incident() {}
    public static Incident newIncident(IncidentType t, String title, String desc,
                                       double lat, double lng, Long reporterId) {
        Incident i = new Incident();
        i.type = t;
        i.title = title;
        i.description = desc;
        i.location = new GeoPoint(lat, lng);
        i.reportedAt = OffsetDateTime.now();
        i.status = "OPEN";
        i.reporterUserId = reporterId != null ? reporterId : 0L;
        return i;
    }

    public Long getId() { return id; }
    public IncidentType getType() { return type; }
    public GeoPoint getLocation() { return location; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
    public OffsetDateTime getReportedAt() { return reportedAt; }
    public Long getReporterUserId() { return reporterUserId; }
    public String getStatus() { return status; }
}

interface IncidentRepository extends JpaRepository<Incident, Long> {
    // Approx Haversine filter (km)
    @Query("""
               SELECT i FROM Incident i
               WHERE (6371 * acos(
                 cos(radians(:lat)) * cos(radians(i.location.lat)) *
                 cos(radians(i.location.lng) - radians(:lng)) +
                 sin(radians(:lat)) * sin(radians(i.location.lat))
               )) <= :radiusKm
               ORDER BY i.reportedAt DESC
            """)
    List<Incident> findNearby(@Param("lat") double lat,
                              @Param("lng") double lng,
                              @Param("radiusKm") double radiusKm);

    /**
     * DTOs
     **/
    class ReportIncidentRequest {
        @NotNull
        private IncidentType type;
        @NotBlank
        private String title;
        @Size(max = 2000)
        private String description;
        @NotNull
        private Double lat;
        @NotNull
        private Double lng;

        public IncidentType getType() {
            return type;
        }

        public String getTitle() {
            return title;
        }

        public String getDescription() {
            return description;
        }

        public Double getLat() {
            return lat;
        }

        public Double getLng() {
            return lng;
        }
    }

    class NearbyQuery {
        @NotNull
        private Double lat;
        @NotNull
        private Double lng;
        @NotNull
        @Positive
        private Double radiusKm;

        public Double getLat() {
            return lat;
        }

        public Double getLng() {
            return lng;
        }

        public Double getRadiusKm() {
            return radiusKm;
        }
    }

    class IncidentResponse {
        private Long id;
        private IncidentType type;
        private String title;
        private String description;
        private double lat;
        private double lng;
        private OffsetDateTime reportedAt;
        private String status;

        public static IncidentResponse from(Incident i) {
            IncidentResponse r = new IncidentResponse();
            r.id = i.getId();
            r.type = i.getType();
            r.title = i.getTitle();
            r.description = i.getDescription();
            r.lat = i.getLocation().getLat();
            r.lng = i.getLocation().getLng();
            r.reportedAt = i.getReportedAt();
            r.status = i.getStatus();
            return r;
        }

        public Long getId() {
            return id;
        }

        public IncidentType getType() {
            return type;
        }

        public String getTitle() {
            return title;
        }

        public String getDescription() {
            return description;
        }

        public double getLat() {
            return lat;
        }

        public double getLng() {
            return lng;
        }

        public OffsetDateTime getReportedAt() {
            return reportedAt;
        }

        public String getStatus() {
            return status;
        }
    }

    /**
     * Service & Controller
     **/
    @Service
    class IncidentService {
        private final IncidentRepository repo;

        IncidentService(IncidentRepository repo) {
            this.repo = repo;
        }

        IncidentResponse report(ReportIncidentRequest r, Long reporterId) {
            Incident saved = repo.save(Incident.newIncident(
                    r.getType(), r.getTitle(), r.getDescription(), r.getLat(), r.getLng(), reporterId));
            return IncidentResponse.from(saved);
        }

        List<IncidentResponse> nearby(double lat, double lng, double radiusKm) {
            return repo.findNearby(lat, lng, radiusKm).stream().map(IncidentResponse::from).toList();
        }
    }

    @RestController
    @RequestMapping("/api/incidents")
    class IncidentController {
        private final IncidentService service;
        private final UserRepository users;

        IncidentController(IncidentService service, UserRepository users) {
            this.service = service;
            this.users = users;
        }

        @PostMapping
        public ResponseEntity<IncidentResponse> report(@Valid @RequestBody ReportIncidentRequest req) {
            // If you want to tie to the authenticated user, parse email from SecurityContext
            // String email = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            // Long reporterId = users.findByEmail(email).map(User::getId).orElse(0L);
            Long reporterId = 0L;
            return ResponseEntity.ok(service.report(req, reporterId));
        }

        @GetMapping("/nearby")
        public ResponseEntity<List<IncidentResponse>> nearby(@Valid NearbyQuery q) {
            return ResponseEntity.ok(service.nearby(q.getLat(), q.getLng(), q.getRadiusKm()));


        }


    }
}