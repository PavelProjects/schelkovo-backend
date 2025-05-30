package ru.pobopo.schelkovo.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import ru.pobopo.schelkovo.dto.AuthenticatedUser;
import ru.pobopo.schelkovo.dto.SpotStatus;
import ru.pobopo.schelkovo.dto.SpotStatusType;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Slf4j
@Service
@RequiredArgsConstructor
public class StatusService {
    private final static Path STORAGE_FILE = Paths.get("./schelkovo_status.json");

    private final AuthenticationService authenticationService;
    private final ObjectMapper objectMapper;

    private SpotStatus currentStatus = new SpotStatus(SpotStatusType.CLOSED, "");

    public SpotStatus getStatus() {
        return currentStatus;
    }

    public void setStatus(SpotStatus request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication.getPrincipal() == null) {
            throw new AccessDeniedException("Not authenticated");
        }
        AuthenticatedUser user = (AuthenticatedUser) authentication.getPrincipal();
        if (!authenticationService.isAdmin(user)) {
            throw new AccessDeniedException("Not an admin");
        }

        try {
            objectMapper.writeValue(STORAGE_FILE.toFile(), request);
            log.trace("Status saved in file {}", STORAGE_FILE);
        } catch (IOException e) {
            log.error("Failed to write status in file: {}", e.getMessage());
            throw new RuntimeException(e.getMessage());
        }

        this.currentStatus = request;
        log.info("User {} changed spot status to {}", user.getName(), request);
    }

    @PostConstruct
    public void loadStatus() throws IOException {
        log.info("Loading status from file {}", STORAGE_FILE);
        if (Files.notExists(STORAGE_FILE)) {
            log.info("No storage file found, using default state - closed");
            return;
        }
        this.currentStatus = objectMapper.readValue(STORAGE_FILE.toFile(), SpotStatus.class);
        log.info("Loaded spot status: {}", currentStatus);
    }
}
