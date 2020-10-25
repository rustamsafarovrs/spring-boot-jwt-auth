package tj.rs.devteam.springbootjwtauth.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import tj.rs.devteam.springbootjwtauth.models.ERole;
import tj.rs.devteam.springbootjwtauth.models.Role;
import tj.rs.devteam.springbootjwtauth.models.User;
import tj.rs.devteam.springbootjwtauth.payload.request.LoginRequest;
import tj.rs.devteam.springbootjwtauth.payload.request.SignupRequest;
import tj.rs.devteam.springbootjwtauth.payload.responce.JwtResponse;
import tj.rs.devteam.springbootjwtauth.payload.responce.MessageResponse;
import tj.rs.devteam.springbootjwtauth.repository.RoleRepository;
import tj.rs.devteam.springbootjwtauth.repository.UserRepository;
import tj.rs.devteam.springbootjwtauth.security.jwt.JwtUtils;
import tj.rs.devteam.springbootjwtauth.security.service.UserDetailsImpl;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager mAuthenticationManager;
    @Autowired
    UserRepository mUserRepository;
    @Autowired
    RoleRepository mRoleRepository;
    @Autowired
    PasswordEncoder mPasswordEncoder;
    @Autowired
    JwtUtils mJwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = mAuthenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = mJwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        if (mUserRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username already taken!"));
        }
        if (mUserRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email already in use!"));
        }

        // Create new user`s account
        User user = new User(signupRequest.getUsername(),
                signupRequest.getEmail(), mPasswordEncoder.encode(signupRequest.getPassword()));

        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = mRoleRepository.existsByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = mRoleRepository.existsByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole =mRoleRepository.existsByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = mRoleRepository.existsByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        user.setRoles(roles);

        mUserRepository.save(user);

        return ResponseEntity.ok(
                new MessageResponse("User registered successfully")
        );
    }
}
