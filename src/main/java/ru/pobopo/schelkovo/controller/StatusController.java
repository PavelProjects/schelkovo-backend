package ru.pobopo.schelkovo.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import ru.pobopo.schelkovo.dto.SpotStatus;
import ru.pobopo.schelkovo.dto.SpotStatusType;
import ru.pobopo.schelkovo.service.StatusService;

@RestController
@RequestMapping("/api/status")
@RequiredArgsConstructor
public class StatusController {
    private final StatusService statusService;

    @GetMapping
    public SpotStatus getStatus() {
        return statusService.getStatus();
    }

    @GetMapping("/list")
    public SpotStatusType[] getStatusesList() {
        return SpotStatusType.values();
    }

    @PatchMapping
    public void setStatus(@RequestBody SpotStatus request) {
        statusService.setStatus(request);
    }
}
